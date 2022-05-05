using System;
using System.IO;
using System.Collections.Generic;
using System.Text.Json;
using SmallTool_MIP.Models;
using System.Linq;
using System.Configuration;
using ConsoleTables;

namespace SmallTool_MIP
{
    public class MIP
    {
        private MIP_Response result = new MIP_Response();
        private readonly string ProgramLocation = System.AppDomain.CurrentDomain.BaseDirectory;
        private readonly static Handler Handler = new Handler();
        private string BaseLocation;
        private MIP_Rules Rule = new MIP_Rules();
        private MIP_AppObject AppInfo = new MIP_AppObject();
        private List<MIP_LogObject> errorlist = new List<MIP_LogObject>();
        private List<MIP_LabelObject> labellist = new List<MIP_LabelObject>();
        private List<MIP_TelemetryObject> telemetrylist = new List<MIP_TelemetryObject>();
        private List<MIP_TelemetryObject> auditlist = new List<MIP_TelemetryObject>();

        public MIP_Response Analyse(string Location)
        {
            result.Flag = true;
            Handler.InitializeLogFile();

            //initialize rule
            Rule = Handler.DeserializeRules(ProgramLocation);

            //initialize MIP location
            BaseLocation = Handler.LocationValidator(Location, Rule.MIPLogOnly);

            if (BaseLocation.Length < 1)
            {
                result.Flag = false;
                result.ErrMessage = "Not a valid mip log path";
                return result;
            }

            if (Rule.MIPMode < 1 || Rule.MIPMode > 6)
            {
                result.ErrMessage = "Invalid Mode in rule";
                return result;
            }

            Rule.Initialize();

            Handler.TxtLogger(Handler.Serialize(Rule));

            List<string> MIPLogs = new List<string>();
            if (!Rule.MIPLogOnly)
            {
                MIPLogs = Directory.GetFiles(BaseLocation, "*.miplog").ToList();
            }
            else
            {
                MIPLogs.Add(BaseLocation);
            }

            if (MIPLogs.Count() > 0)
            {

                foreach (string path in MIPLogs)
                {
                    //open file
                    string[] RawContent = File.ReadAllLines(path).ToArray();
                    string LogFileName = path;

                    Console.WriteLine("\n++++++++" + LogFileName + "++++++++");

                    //initially parse log

                    Dictionary<int, string> ParsedContent = ParseMIPLog(RawContent);
                    foreach (KeyValuePair<int, string> entry in ParsedContent)
                    {
                        if (Handler.IsFiltered(entry.Value, "MIP_Telemetry") | Handler.IsFiltered(entry.Value, "MIP_Audit")) //Filter telemetry info
                        {
                            LogAnalyse(ParsedContent, entry.Key, entry.Value, telemetrylist, auditlist);
                        }
                        else
                        {
                            String[] list = Handler.SplitLog(entry.Value);

                            if (Handler.IsStart(list[0], "MIP_Error"))
                            {
                                ErrorAnalyse(entry.Key, list, errorlist);
                            }
                            else if (Handler.IsStart(list[0], "MIP_Trace"))
                            {
                                if (Handler.IsStart(list[4].Trim(), "MIP_Label")) //filer label information
                                {
                                    LabelAnalyse(list[4], labellist);
                                }
                                else if (Handler.IsStart(list[4].Trim(), "MIP_Co-auth"))

                                {
                                    AppInfo.Coauth = list[4].Replace('"', ' ').Trim();
                                }
                                else
                                {
                                    continue;//Bypass other trace
                                }
                            }
                            else if (Handler.IsStart(list[0], "MIP_Info")) // For other Info module
                            {
                                if (Handler.IsStart(list[4].Trim(), "MIP_Co-auth"))
                                {
                                    AppInfo.Coauth = list[4].Replace('"', ' ').Trim();
                                }
                                else
                                {
                                    continue;
                                }
                            }
                        }
                    }

                    //get app info from first telemetry data, if no telemetry, check audit
                    Dictionary<int, string> AppData = new Dictionary<int, string>();

                    if (telemetrylist.Count() > 0 | auditlist.Count() > 0)
                    {
                        if (telemetrylist.Count() > 0)
                        {
                            AppData = telemetrylist[0].TelemetryList;
                        }
                        else if (auditlist.Count() > 0)
                        {
                            AppData = auditlist[0].TelemetryList;
                        }

                        foreach (KeyValuePair<int, string> entry in AppData)
                        {

                            int pTo = entry.Value.IndexOf(":");

                            int sFrom = entry.Value.IndexOf("[");
                            int sTo = entry.Value.IndexOf("]");

                            switch (entry.Value.Substring(1, pTo - 1))
                            {
                                case "App.ApplicationId":
                                    AppInfo.ApplicationId = entry.Value.Substring(sFrom, sTo - sFrom + 1);
                                    break;

                                case "App.ApplicationName":
                                    AppInfo.ApplicationName = entry.Value.Substring(sFrom, sTo - sFrom + 1);
                                    break;

                                case "App.ApplicationVersion":
                                    AppInfo.ApplicationVersion = entry.Value.Substring(sFrom, sTo - sFrom + 1);
                                    break;

                                case "MIP.Version":
                                    AppInfo.MIPVersion = entry.Value.Substring(sFrom, sTo - sFrom + 1);
                                    break;
                            }
                        }
                    }
                    else // no trace
                    {
                        continue;
                    }

                    // Analyze based on rules
                    if (Rule.Bootstrap)
                    {
                        BootstrapAnalyse(AppInfo);
                    }

                    if (Rule.ErrorOnly)
                    {
                        ErrorInformation(errorlist);
                    }

                    if (Rule.Label)
                    {
                        LabelInformation(labellist);
                    }

                    if (Rule.Trace == "verbose")
                    {
                        TelemetryInformation(telemetrylist, "telemetry");
                        TelemetryInformation(AuditInformation(auditlist), "audit");
                    }
                    if (Rule.Trace == "simple")
                    {
                        SimpleTelemetryInformation(telemetrylist, "telemetry");
                        SimpleTelemetryInformation(AuditInformation(auditlist), "audit");
                    }
                    
                }
            }
            return result;
        }

        private Dictionary<int, string> ParseMIPLog(string[] RawContent)
        {
            // Add line number to log file
            Dictionary<int, string> ParsedContent = new Dictionary<int, string>();

            foreach (var Item in RawContent.Select((value, i) => (value, i)))
            {
                string Line = Item.value;
                int Index = Item.i;
                if (Line.Length > 0)
                {
                    string[] LineInfo = { Index.ToString(), Line };

                    ParsedContent.Add(Index, Line);
                }
            }
            return ParsedContent;
        }



        private void LabelAnalyse(string content, List<MIP_LabelObject> labellist)
        {
            string[] IDs = content.Split(",");
            if (Handler.IsStart(IDs[0].Trim(), "MIP_Label") & Handler.IsStart(IDs[1].Trim(), "MIP_Template"))
            {
                MIP_LabelObject labeldata = new MIP_LabelObject();
                labeldata.LabelID = IDs[0].Trim().Split('[', ']')[1];
                labeldata.TemplateId = IDs[1].Trim().Split('[', ']')[1];
                labellist.Add(labeldata);
            }
        }

        private void LogAnalyse(Dictionary<int, string> raw, int index, string content, List<MIP_TelemetryObject> telemetrylist, List<MIP_TelemetryObject> auditlist)
        {
            MIP_TelemetryObject telemetryobject = new MIP_TelemetryObject();
            MIP_TelemetryObject auditobject = new MIP_TelemetryObject();

            //get telemetry message
            String[] list=Handler.SplitLog(content);

            //split first line to get time, process
            Dictionary<int, string> telemetry = new Dictionary<int, string>();
            string eventtime = list[1];
            string process = list[3];
            string eventname = list[4].Split('[', ']')[1];

            // get event details
            int i = index + 1;

            while (raw[i].StartsWith("\t"))
            {
                telemetry.Add(i,raw[i]);
                i++;
            }
            //split audit and others
            if (eventname.Contains("audit"))
            {
                auditobject.EventTime = eventtime;
                auditobject.EventName = eventname;
                auditobject.Process = process;
                auditobject.TelemetryList = telemetry;
                auditlist.Add(auditobject);
            }
            else
            {
                telemetryobject.EventTime = eventtime;
                telemetryobject.EventName = eventname;
                telemetryobject.Process = process;
                telemetryobject.TelemetryList = telemetry;
                telemetrylist.Add(telemetryobject);
            }
        }

        private void ErrorAnalyse(int index, string[] content, List<MIP_LogObject> errorlist)
        {
            MIP_LogObject data = new MIP_LogObject();
            data.Line = index.ToString();
            data.Level = content[0];
            data.Date = content[1];
            data.Logger = content[2];
            data.Process = content[3];
            data.Message = content[4];
            data.StackTrace = content[5];
            data.ThreadId = content[6];

            errorlist.Add(data);
        }


        private void BootstrapAnalyse(MIP_AppObject AppInfo)
        {
            Console.WriteLine("++++++++Bootstrap++++++++\n");

            var table = new ConsoleTable("Info", "Result");
            table.AddRow("Application Id: ", AppInfo.ApplicationId);
            table.AddRow("Application Name: ", AppInfo.ApplicationName);
            table.AddRow("Application Version: ", AppInfo.ApplicationVersion);
            table.AddRow("MIP SDK Version: ", AppInfo.MIPVersion);
            table.AddRow("Co-auth status: ", AppInfo.Coauth);
            table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
            Console.WriteLine("\n++++++++Bootstrap++++++++");
            Console.WriteLine("");
        }

        private void LabelInformation(List<MIP_LabelObject> labellist)
        {
            Console.WriteLine("++++++++Label Information++++++++\n");
            var table = new ConsoleTable("LabelID", "TemplateID");

            var DistinctItems = labellist.GroupBy(x => x.LabelID).Select(y => y.First()); // get distinct labellist by labelID
            foreach (MIP_LabelObject lableoutput in DistinctItems)
            {
                table.AddRow(lableoutput.LabelID, lableoutput.TemplateId);
            }
            table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
            Console.WriteLine("\n++++++++Label Information++++++++");
            Console.WriteLine("");
        }

        private void ErrorInformation(List<MIP_LogObject> errorlist)
        {
            List<string> Erroroutput = new List<string>();

            // generate error list
            foreach (MIP_LogObject error in errorlist)
            {
                if (Handler.IsFiltered(error.Message.Trim(), "MIP_ByPassError")) //Bypass some unuseful error message
                    continue;
                else
                {
                    bool exists = Erroroutput.Contains(error.Message.ToString()); // get distinct error list 
                    if (exists)
                    {
                        continue;
                    }
                    else
                    {
                        String St = error.Message.ToString();
                        int pFrom = St.IndexOf("[");
                        int pTo = St.LastIndexOf("]");
                        if (pFrom >= 0 & pTo > 0)
                        {
                            String result = St.Substring(pFrom, pTo - pFrom + 1);
                            
                            Erroroutput.Add("Error line: " + error.Line + "\n" + "Error time: " + error.Date + "\n" + "Process name: " + error.Process + "\n" + result);
                        }
                        else
                        {
                            Erroroutput.Add("Error line: " + error.Line + "\n" + "Error time: " + error.Date + "\n" + "Process name: " + error.Process + "\n"+ St);
                        }
                    }
                }
            }

            Console.WriteLine("++++++++Error Message++++++++\n");

            foreach (string line in Erroroutput) //display error
            {
                Console.WriteLine(line + "\n");
            }

            Console.WriteLine("\n++++++++Error Message++++++++");
        }

        private void TelemetryInformation(List<MIP_TelemetryObject> telemetrylist, string category)
        {
            // Display verbose telemetry information

            if (category == "telemetry")
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
            }
            else
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
            }

            //var distincttelemetry = telemetrylist.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
            //Console.WriteLine("The number of event: " + distincttelemetry.Count());
            var grouptelemetry = telemetrylist.GroupBy(x => x.Process);// get distinct telemetrylist by eventname
            

            //Output
            foreach (var singletelemetry in grouptelemetry) 
            {
                var distincttelemetry = singletelemetry.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
                Console.WriteLine( "The number of event: " + distincttelemetry.Count() +"\n");

                int count = 1; //counter of event

                foreach (MIP_TelemetryObject telemetry in distincttelemetry)
                {
                    
                    Console.WriteLine("\n++++++++NO. {0}++++++++", count);
                    var table = new ConsoleTable("Info", "Value");
                    table.AddRow("Event name: ", telemetry.EventName.Trim());
                    table.AddRow("Event Time: ", telemetry.EventTime.Trim());
                    table.AddRow("Process: ", telemetry.Process.Trim());
                    table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

                    string output = new string("");
                    foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
                    {
                        // Display line number and message
                        Console.WriteLine(item.Key.ToString() + item.Value);
                    }
                    //table.AddRow("Event Info: ", output);
                    Console.WriteLine("\n++++++++NO. {0}++++++++",count);
                    Console.WriteLine("");

                    count++;
                }
                if (category == "telemetry")
                {
                    Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
                }
                else
                {
                    Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
                }
                Console.WriteLine("");
            }
            
        }
        private void SimpleTelemetryInformation(List<MIP_TelemetryObject> telemetrylist, string category)
        {
            if (category == "telemetry")
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
            }
            else
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
            }

            //Output

            //var distincttelemetry = telemetrylist.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
            //Console.WriteLine("The number of event: " + distincttelemetry.Count());

            var grouptelemetry = telemetrylist.GroupBy(x => x.Process); // Group by process name

            foreach (var singletelemetry in grouptelemetry)
            {
                var distincttelemetry = singletelemetry.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
                Console.WriteLine("The number of event: " + distincttelemetry.Count());
                foreach (MIP_TelemetryObject telemetry in distincttelemetry)
                {
                    MIP_TelemetryObject filteredTelemetry = TelemetryFilter(telemetry); //Fliter simple telemetry info

                    if (filteredTelemetry.TelemetryList.Count() > 3)
                    {
                        var table = new ConsoleTable("Line", "Info", "Value");
                        table.AddRow("", "Event name: ", filteredTelemetry.EventName);
                        table.AddRow("", "Event Time: ", filteredTelemetry.EventTime.Trim());
                        table.AddRow("", "Process: ", telemetry.Process.Trim());
                        //table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

                        string output = new string("");
                        foreach (KeyValuePair<int, string> item in filteredTelemetry.TelemetryList)
                        {
                            //Console.WriteLine(item.Substring(0, item.LastIndexOf(',')));
                            string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                            var value = keyPair.Trim().Split(new[] { ':' }, 2);
                            table.AddRow(item.Key, value[0], value[1]);
                        }
                        table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                    }
                    else
                    {
                        continue;
                    }
                    //table.AddRow("Event Info: ", output);
                    if (category == "telemetry")
                    {
                        Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
                    }
                    else
                    {
                        Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
                    }
                    Console.WriteLine("");
                }
                Console.WriteLine("");
            }
        }

        private MIP_TelemetryObject TelemetryFilter(MIP_TelemetryObject input)
        {
            MIP_TelemetryObject output = new MIP_TelemetryObject();

            Dictionary<int, string> outTeleList = new Dictionary<int, string>();

            //use flag to capture
            int sFlag = 0;
            int eFlag = input.TelemetryList.Count();

            // add message which contains error info to output
            foreach (KeyValuePair<int, string> item in input.TelemetryList) // scan error related information
            {
                if (Handler.IsFiltered(item.Value, "MIP_TelemetryError_1") | Handler.IsFiltered(item.Value, "MIP_TelemetryError_2"))
                {
                    outTeleList.Add(item.Key,item.Value);
                }
            }
            foreach (KeyValuePair<int, string> item in input.TelemetryList) // get range of useful telemetry
            {
                if (Handler.IsStart(item.Value.Trim(), "MIP_TelemetryStartFlag"))
                    //(item.Value.StartsWith("\tEventInfo.PrivTags"))
                {
                    sFlag = item.Key;
                }
                if (Handler.IsStart(item.Value.Trim(), "MIP_TelemetryEndFlag"))
                //(item.Value.StartsWith("\tiKey"))
                {
                    eFlag = item.Key;
                }
            }

            for (int i = sFlag + 1; i < eFlag; i++)
            {
                outTeleList.Add(i,input.TelemetryList[i]);
            }
            output.EventTime = input.EventTime;
            output.EventName = input.EventName;
            output.TelemetryList = outTeleList;

            return output;
        }

        private List<MIP_TelemetryObject> AuditInformation(List<MIP_TelemetryObject> auditlist)
        {
            // get audit output
            List<MIP_TelemetryObject> auditoutput = new List<MIP_TelemetryObject>();
            foreach (MIP_TelemetryObject telemetry in auditlist)
            {
                bool flag = true;
                foreach (KeyValuePair<int, string> entry in telemetry.TelemetryList)
                {
                    if (Handler.IsFiltered(entry.Value, "MIP_AuditFilter_1") | Handler.IsFiltered(entry.Value, "MIP_AuditFilter_2")) //bypass useless audit
                    {
                        flag = false;
                    }
                }
                if (flag)
                {
                    auditoutput.Add(telemetry);
                }
            }
            return auditoutput;
        }

    }
}


