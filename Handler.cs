﻿using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Text.Json;
using SmallTool_MIP.Models;
using System.Linq;
using System.Data.SQLite;
using System.Data;


namespace SmallTool_MIP
{
    class Handler
    {
        private readonly string ProgramLocation = System.AppDomain.CurrentDomain.BaseDirectory;
        private string CurrentLogFile;
        private static SQLiteConnection db = new SQLiteConnection("DataSource = database.db; Version = 3;");
        private readonly static Dictionary<string, string> ColumnFilter = InitializeColumnFilter();
        Regex LogSplit = new Regex("(?:^|\t)([\t]\"[^\"\t](?:[^\"])*\"[\t]|[^\t]*)", RegexOptions.Compiled);
        Regex TimeSplit = new Regex("(?:^|\t)([\t]\"[^\"\t](?:[^\"])*\\][\t]|[^\t]*)", RegexOptions.Compiled);

        public void InitializeLogFile()
        {
            string LogPath = ProgramLocation + @"\mipLogs\";
            Directory.CreateDirectory(LogPath);

            string[] LogFiles = Directory.GetFiles(LogPath, "Log-*");
            if (LogFiles.Length > 0)
            {
                List<string> Files = LogFiles.ToList();
                int FileNumber = 0;
                foreach (string file in Files)
                {
                    Int32.TryParse(file.Split('\\')[^1].Split('-')[^1].Split('.')[0], out int TempFileNumber);
                    if (TempFileNumber > FileNumber) { FileNumber = TempFileNumber; }
                }

                FileNumber++;
                CurrentLogFile = LogPath + "Log-" + FileNumber + ".log";
                File.Create(CurrentLogFile).Close();
            }
            else
            {
                CurrentLogFile = LogPath + @"Log-1.log";
                File.Create(CurrentLogFile).Close();
            }
        }

        //try to complete the validated MIP folder path
        public string LocationValidator(string Location)
        {
            if (!File.Exists(Location))
            {
                return "";
            }
            return Location;
        }

        public string Serialize(Object input)
        {
            string Output = JsonSerializer.Serialize(input, new JsonSerializerOptions());

            return Output;
        }

        public MIP_Rules DeserializeRules(string ProgramLocation)
        {
            try
            {
                return JsonSerializer.Deserialize<MIP_Rules>(File.ReadAllText(ProgramLocation + "rules.json"));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return new MIP_Rules();
            }
        }

        //public string XmlValidator(string Location)
        //{
        //    string content = File.ReadAllText(Location, Encoding.Unicode);
        //    content = content.Replace("\x00", "[0x00]").Replace(@"\0", "");
        //    content = "<WRAPPER>" + content + @"</WRAPPER>";
        //    return content;
        //}

        public void TxtLogger(string[] input)
        {
            try
            {
                foreach (string item in input)
                {
                    File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + "    " + item + "\n");
                    //Trace.Flush();
                }
            }
            catch (Exception e)
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + e);
            }
        }

        public void TxtLogger(string input)
        {
            try
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + "    " + input + "\n");
                //Trace.Flush();
            }
            catch (Exception e)
            {
                File.AppendAllText(CurrentLogFile, DateTime.Now.ToString() + e + "\n");
            }
        }

        private static DataTable DBSet()
        {
            db.Open();

            string sql = "select * from mipDB";
            SQLiteCommand command = new SQLiteCommand(sql, db);
            SQLiteDataReader reader = command.ExecuteReader();

            DataTable dt = new DataTable("Filter");

            if (reader.HasRows)
            {
                dt.Load(reader);
            }

            db.Close();

            return dt;
        }

        private static Dictionary<string,string> InitializeColumnFilter()
        {
            db.Open();

            string sql = "select * from mipDB";
            SQLiteCommand command = new SQLiteCommand(sql, db);
            SQLiteDataReader reader = command.ExecuteReader();

            DataTable dt = new DataTable("Filter");

            if (reader.HasRows)
            {
                dt.Load(reader);
            }

            db.Close();

            Dictionary<string, string> output = new Dictionary<string, string>();

            foreach (DataRow row in dt.Rows)
            {
                output.Add(row["name"].ToString(), row["value"].ToString());
            }

            return output;
        }

        public bool IsFiltered(string input, string KeyWord)
        {
            return input.Contains(ColumnFilter[KeyWord]);
        }

        public bool IsStart(string input, string KeyWord)
        {
            return input.StartsWith(ColumnFilter[KeyWord]);
        }

        public bool IsFiltered(string input, string[] KeyWord)
        {
            foreach (string word in KeyWord)
            {
                if (IsFiltered(input, word))
                {
                    return true;
                }
            }
            return false;
        }

        public bool Contains(string input, string[] KeyWord)
        { 
            foreach (string word in KeyWord)
            {
                if (input.Contains(word))
                {
                    return true;
                }
            }
            return false;
        }

        public string SubstringString(string input, string KeyWord)
        {
            string output;

            output = input.Substring(input.IndexOf(ColumnFilter[KeyWord]) + ColumnFilter[KeyWord].Length);

            return output;
        }

        public List<List<string[]>> ListGroup(List<List<string[]>> input)
        {
            //List<List<string[]>> output = new List<List<string[]>>();
            List<List<string[]>> tempoutput = new List<List<string[]>>();
            List<string[]> temp = new List<string[]>();
            if (input.Count > 0)
            {
                //output.Add(input[0]);
                tempoutput.Add(input[0]);
                foreach(var list in input.Skip(1).ToList())
                {
                    bool Found = false;
                    foreach (var outlist in tempoutput)
                    {
                        if (list.Count == outlist.Count)
                        {
                            temp = new List<string[]>();
                            foreach (string[] arr in outlist)
                            {
                                if (!list.Any(a => a.SequenceEqual(arr)))
                                {
                                    temp.Add(arr);
                                }
                            }
                            if (temp.Count == 0)
                            {
                                Found = true;
                            }
                        }
                    }
                    if (!Found)
                    {
                        tempoutput.Add(list);
                    }
                }
            }
            return tempoutput;
        }

        //public bool IsMSIPCRequest(string input)
        //{
        //    //return input.StartsWith("Initializing an HTTP request with Win");
        //    string KeyWord = ColumnFilter["MSIPC_Request"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCReponse(string input)
        //{
        //    //return input.StartsWith("------ Sending Request done. HTTP Status code = ");
        //    string KeyWord = ColumnFilter["MSIPC_Response"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCCorrelation(string input)
        //{
        //    //return input.StartsWith("Correlation-Id/Request-Id:");
        //    string KeyWord = ColumnFilter["MSIPC_Correlation"];
        //    return IsFiltered(input, KeyWord);
        //}

        //public bool IsMSIPCBasicLog(string input)
        //{
        //    return IsMSIPCRequest(input) || IsMSIPCReponse(input) || IsMSIPCCorrelation(input);
        //}

        //public List<string> GetEmails(string input)
        //{
        //    List<string> output = new List<string>();

        //    Regex emailRegex = new Regex(@"\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*", RegexOptions.IgnoreCase);
        //    MatchCollection emailMatches = emailRegex.Matches(input);
        //    foreach (Match emailMatch in emailMatches)
        //    {
        //        output.Add(emailMatch.Value);
        //    }

        //    return output;
        //}


        //get string between {}
        //public List<string> GetIds(string input)
        //{
        //    List<string> output = new List<string>();

        //    Regex CurlyBracesRegex = new Regex(@"{(.*?)}", RegexOptions.IgnoreCase);
        //    Regex DoubleQuotesRegex = new Regex("\"([^\"]*)\"", RegexOptions.IgnoreCase);
        //    MatchCollection IdMatches = CurlyBracesRegex.Matches(input);
        //    if (IdMatches.Count == 0)
        //    {
        //        IdMatches = DoubleQuotesRegex.Matches(input);
        //    }

        //    foreach (Match IdMatch in IdMatches)
        //    {
        //        output.Add(IdMatch.Groups[1].Value);
        //    }

        //    return output;
        //}

        //get string between { }
        public string[] SplitLog(string item)
        {
            
            List<string> list = new List<string>();
            string curr = null;
            foreach (Match match in LogSplit.Matches(item))
            {
                curr = match.Value;
                if (0 == curr.Length)
                {
                    list.Add("");
                }

                list.Add(curr.TrimStart(' '));
            }

            return list.ToArray();
        }
    }
}
