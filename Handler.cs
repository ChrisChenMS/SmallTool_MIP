using System;
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
        public string LocationValidator(string Location, bool LogOnly)
        {
            if (!File.Exists(Location) & !Directory.Exists(Location))
            {
                return "";
            }

            //check folder
            if (!LogOnly)
            {
                try
                {
                    //check if miplog in logs folder
                    if (!Directory.EnumerateFiles(Location, "*.miplog").Any())
                    {
                        //check if miplog in mip\logs folder
                        if (!Directory.EnumerateFiles(Location + @"\logs\", "*.miplog").Any())
                        {
                            return "";
                        }
                        else
                        {
                            return (Location + @"\logs\");
                        }
                    }
                    else
                    {
                        return Location;
                    }
                }
                catch (Exception e)
                {
                    File.AppendAllText(Location, DateTime.Now.ToString() + e + "\n");
                }
            }
            else
            //check file
            {
                if (!File.Exists(Location))
                {
                    return "";
                }
                else
                {
                    return Location;
                }
            }
            return "";
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

        //split log using Regex
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
