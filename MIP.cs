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

            if (Rule.MIPMode < 1 || Rule.MIPMode > 5)
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

                    List<MIP_TelemetryObject> telemetrylist = new List<MIP_TelemetryObject>();
                    List<MIP_TelemetryObject> auditlist = new List<MIP_TelemetryObject>();
                    List<MIP_LogObject> errorlist = new List<MIP_LogObject>();
                    List<MIP_LabelObject> labellist = new List<MIP_LabelObject>();
                    MIP_AppObject AppInfo = new MIP_AppObject();

                    Console.WriteLine("\n++++++++" + LogFileName + "++++++++");
                    
                    //initially parse log

                    Dictionary<int, string> ParsedContent = Handler.ParseMIPLog(RawContent);

                    //get time range from input
                    Console.WriteLine("Input the Time Range. Format yyyy-MM-dd HH:mm:ss");
                    DateTime start = new DateTime();
                    while (true)
                    {
                        Console.WriteLine("Start Time(yyyy-MM-dd HH:mm:ss):");
                        var startInput = Console.ReadLine();
                        DateTime startResult;
                        if (!DateTime.TryParse(startInput, out startResult))
                        {
                            // handle parse failure
                            Console.WriteLine("Start Time with Format Error! Try again...");
                        }
                        else
                        {
                            start = startResult;
                            break;
                        }
                    }

                    Console.WriteLine("End Time(yyyy-MM-dd HH:mm:ss):");
                    DateTime end = DateTime.Now;
                    while (true)
                    {
                        var endInput = Console.ReadLine();
                        DateTime endResult;
                        if (!DateTime.TryParse(endInput, out endResult))
                        {
                            // handle parse failure
                            Console.WriteLine("End Time with Format Error! Try again...");
                        }
                        else if (endResult<start)
                        {
                            Console.WriteLine("End Time should not be earlier than Start Time. Try again...");
                        }
                        else
                        {
                            end = endResult;
                            break;
                        }
                    }

                    ParsedContent=Handler.TimeFilter(ParsedContent,start,end); //get log between time range

                    foreach (KeyValuePair<int, string> entry in ParsedContent)
                    {
                        if (Handler.IsFiltered(entry.Value, "MIP_Telemetry") || Handler.IsFiltered(entry.Value, "MIP_Audit")) //Filter telemetry info
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

                            foreach (KeyValuePair<int, string> appentry in AppData)
                            {

                                int pTo = appentry.Value.IndexOf(":");

                                int sFrom = appentry.Value.IndexOf("[");
                                int sTo = appentry.Value.IndexOf("]");

                                switch (appentry.Value.Substring(1, pTo - 1))
                                {
                                    case "App.ApplicationId":
                                        AppInfo.ApplicationId = appentry.Value.Substring(sFrom, sTo - sFrom + 1);
                                        break;

                                    case "App.ApplicationName":
                                        AppInfo.ApplicationName = appentry.Value.Substring(sFrom, sTo - sFrom + 1);
                                        break;

                                    case "App.ApplicationVersion":
                                        AppInfo.ApplicationVersion = appentry.Value.Substring(sFrom, sTo - sFrom + 1);
                                        break;

                                    case "MIP.Version":
                                        AppInfo.MIPVersion = appentry.Value.Substring(sFrom, sTo - sFrom + 1);
                                        break;
                                }
                            }
                        }
                        else // no trace
                        {
                            continue;
                        }
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

                    if (Rule.Trace)
                    {
                        TelemetryInformation(telemetrylist, "telemetry");
                        TelemetryInformation(AuditInformation(auditlist), "audit");
                    }
                }
            }
            return result;
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
            string thread = "0";
            // get event details
            int i = index + 1;

            while (raw[i].StartsWith("\t"))
            {
                telemetry.Add(i,raw[i]);
                i++;
            }
            
            if (raw[i].StartsWith("\""))
            {
                thread = raw[i].Split('	').Last();
            }
            //split audit and others
            if (eventname.Contains("audit"))
            {
                auditobject.EventTime = eventtime;
                auditobject.EventName = eventname;
                auditobject.Process = process;
                auditobject.TelemetryList = telemetry;
                auditobject.ThreadId = thread;
                auditlist.Add(auditobject);
            }
            else
            {
                telemetryobject.EventTime = eventtime;
                telemetryobject.EventName = eventname;
                telemetryobject.Process = process;
                telemetryobject.TelemetryList = telemetry;
                telemetryobject.ThreadId = thread;
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
            Console.WriteLine("++++++++Bootstrap Table++++++++\n");

            var table = new ConsoleTable("Info", "Result");
            table.AddRow("Application Id: ", AppInfo.ApplicationId);
            table.AddRow("Application Name: ", AppInfo.ApplicationName);
            table.AddRow("Application Version: ", AppInfo.ApplicationVersion);
            table.AddRow("MIP SDK Version: ", AppInfo.MIPVersion);
            table.AddRow("Co-auth status: ", AppInfo.Coauth);
            table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

            Console.WriteLine("");
        }

        private void LabelInformation(List<MIP_LabelObject> labellist)
        {
            Console.WriteLine("++++++++Label Information Begin..++++++++\n");
            var table = new ConsoleTable("LabelID", "TemplateID");

            var DistinctItems = labellist.GroupBy(x => x.LabelID).Select(y => y.First()); // get distinct labellist by labelID
            foreach (MIP_LabelObject lableoutput in DistinctItems)
            {
                table.AddRow(lableoutput.LabelID, lableoutput.TemplateId);
            }
            table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
            Console.WriteLine("\n++++++++Label Information End.++++++++");
            Console.WriteLine("");
        }

        private void ErrorInformation(List<MIP_LogObject> errorlist)
        {
            List<string> Erroroutput = new List<string>();
            if (errorlist.Count() == 0)
            {
                Console.WriteLine("No Error in this log.\n");
            }
            else if (errorlist.Count() > 0)
            {
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
                                Erroroutput.Add("Error line: " + error.Line + "\n" + "Error time: " + error.Date + "\n" + "Process name: " + error.Process + "\n" + St);
                            }
                        }
                    }
                }
                Console.WriteLine("++++++++Error Message Begin..++++++++\n");
                if (Erroroutput.Count() > 0)
                {
                    foreach (string line in Erroroutput) //display error
                    {
                        Console.WriteLine(line + "\n");
                    }
                }
                else
                {
                    Console.WriteLine("No Filtered Error in this log.\n");
                }
                Console.WriteLine("\n++++++++Error Message End.++++++++");
            }
        }

        //private void TelemetryInformation(List<MIP_TelemetryObject> telemetrylist, string category)
        //{
        //    // Display verbose telemetry information

        //    if (category == "telemetry")
        //    {
        //        Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
        //    }
        //    else
        //    {
        //        Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
        //    }

        //    //var distincttelemetry = telemetrylist.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
        //    //Console.WriteLine("The number of event: " + distincttelemetry.Count());
        //    var grouptelemetry = telemetrylist.GroupBy(x => x.Process);// get telemetrylist by process name
            

        //    //Output
        //    foreach (var singletelemetry in grouptelemetry) 
        //    {
        //        var distincttelemetry = singletelemetry.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
        //        Console.WriteLine( "The number of event: " + distincttelemetry.Count() +"\n");

        //        int count = 1; //counter of event

        //        foreach (MIP_TelemetryObject telemetry in distincttelemetry)
        //        {
                    
        //            Console.WriteLine("\n++++++++NO. {0}++++++++", count);
        //            var table = new ConsoleTable("Info", "Value");
        //            table.AddRow("Event name: ", telemetry.EventName.Trim());
        //            table.AddRow("Event Time: ", telemetry.EventTime.Trim());
        //            table.AddRow("Process: ", telemetry.Process.Trim());
        //            table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

        //            string output = new string("");
        //            foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
        //            {
        //                // Display line number and message
        //                Console.WriteLine(item.Key.ToString() + item.Value);
        //            }
        //            //table.AddRow("Event Info: ", output);
        //            Console.WriteLine("\n++++++++NO. {0}++++++++",count);
        //            Console.WriteLine("");

        //            count++;
        //        }
        //        if (category == "telemetry")
        //        {
        //            Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information");
        //        }
        //        else
        //        {
        //            Console.WriteLine("\n++++++++{0}++++++++", "Audit Information");
        //        }
        //        Console.WriteLine("");
        //    }
            
        //}
        private void TelemetryInformation(List<MIP_TelemetryObject> telemetrylist, string category)
        {
            if (category == "telemetry")
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information Begin..");
            }
            else
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Audit Information Begin..");
            }

            //Output

            //var distincttelemetry = telemetrylist.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
            //Console.WriteLine("The number of event: " + distincttelemetry.Count());

            if (telemetrylist.Count == 0)
            {
                Console.WriteLine("No Trace to display.");
            }
            else
            {
                var grouptelemetry = telemetrylist.GroupBy(x => x.Process); // Group by process name
                Console.WriteLine("Group by Process.");

                foreach (var singletelemetry in grouptelemetry)
                {
                    Console.WriteLine("Process Name: " + singletelemetry.Key.Trim());
                    //var distincttelemetry = singletelemetry.GroupBy(x => x.EventName).Select(y => y.First());// get distinct telemetrylist by eventname
                    //Console.WriteLine("The number of event: " + distincttelemetry.Count());

                    //for test
                    List<string> otherevent = new List<string>();
                    Dictionary<string, string> healthdic = new Dictionary<string, string>();

                    
                    //check healthy status of each event, use keyvaluepair eventname,healthstatus
                    foreach (var item in singletelemetry)
                    {
                        bool status = Handler.TelemetryHealthy(item);
                        string name = item.EventName;
                        if (healthdic.ContainsKey(name))
                        {
                            if (!status)
                            {
                                healthdic[name] = "Unhealthy";
                            }
                        }
                        else
                        {
                            if (status)
                            {
                                healthdic.Add(name, "OK");
                            }
                            else
                            {
                                healthdic.Add(name, "Unhealthy");
                            }
                        }
                    }

                    var distincttelemetry = singletelemetry;
                    Console.WriteLine("The number of event: " + distincttelemetry.Count());

                    Console.WriteLine("\n++++++++{0}++++++++", "Event Check Table");

                    var table = new ConsoleTable("EventName", "Number", "Status");


                    foreach (var line in distincttelemetry.GroupBy(info => info.EventName) //get account of each event
                            .Select(group => new {
                                Metric = group.Key,
                                Count = group.Count()
                            })
                            .OrderBy(x => x.Metric))
                    {
                        table.AddRow(line.Metric, line.Count, healthdic[line.Metric]);
                    }
                    table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative); //Output event status table
                    

                    distincttelemetry.GroupBy(x => x.ThreadId).Select(y => y.Last());// get distinct telemetrylist by threadid
                                                                                     //int eventflag = 0;

                    var infoTable = new ConsoleTable("Line", "Time", "EventName", "Action", "Value");


                    foreach (MIP_TelemetryObject telemetry in distincttelemetry)
                    {
                        if (!Handler.EventFilter(telemetry.EventName, "MIP_EventName"))
                        {
                            otherevent.Add(telemetry.EventName);
                        }

                        // Show customized info
                       

                        if (Handler.EventFilter(telemetry.EventName, "MIP_CustomTelemetry"))
                        {
                            if (Handler.IsEqual(telemetry.EventName, "MIP_DefaultLabelKey")) //1
                            {
                                foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
                                {
                                    if (Handler.IsFiltered(item.Value, "MIP_DefaultLabelValue"))
                                    {
                                        string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                                        var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                        infoTable.AddRow(item.Key, telemetry.EventTime.Trim(), telemetry.EventName, value[0], value[1]);
                                    }
                                }
                            }
                            if (Handler.IsEqual(telemetry.EventName, "MIP_SetProtectionKey")) //2
                            {
                                foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
                                {
                                    if (Handler.IsFiltered(item.Value, "MIP_SetProtectionValue"))
                                    {
                                        string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                                        var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                        infoTable.AddRow(item.Key, telemetry.EventTime.Trim(), telemetry.EventName, value[0], value[1]);
                                    }
                                }
                            }

                            if (Handler.IsEqual(telemetry.EventName, "MIP_GetTemplateKey")) //3
                            {
                                foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
                                {
                                    if (Handler.IsFiltered(item.Value, "MIP_SetProtectionValue"))
                                    {
                                        string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                                        var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                        infoTable.AddRow(item.Key, telemetry.EventTime.Trim(), telemetry.EventName, value[0], value[1]);
                                    }
                                }
                            }

                            if (Handler.IsEqual(telemetry.EventName, "MIP_DeleteLabelKey")) //4
                            {
                                foreach (KeyValuePair<int, string> item in telemetry.TelemetryList)
                                {
                                    if (Handler.IsFilteredArray(item.Value, "MIP_DeleteLabelValue"))
                                    {
                                        //split key and vaule by colon to write to table
                                        string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(","));
                                        var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                        infoTable.AddRow(item.Key, telemetry.EventTime.Trim(), telemetry.EventName, value[0], value[1]);
                                    }
                                }
                            }
                        }
                        

                        //Fliter simple telemetry info
                        MIP_TelemetryObject filteredTelemetry = TelemetryFilter(telemetry);
                        //MIP_TelemetryObject filteredTelemetry = telemetry;

                        //Show Connection Telemetry
                        var connectioneTable = new ConsoleTable("Line", "Info", "Value");
                        if (Handler.EventFilter(telemetry.EventName, "MIP_ConnectTelemetry"))
                        {
                            //Process Connection Information
                            connectioneTable.AddRow("", "Event name: ", filteredTelemetry.EventName);
                            connectioneTable.AddRow("", "Event Time: ", filteredTelemetry.EventTime.Trim());
                            connectioneTable.AddRow("", "Process: ", telemetry.Process.Trim());
                            //table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

                            Dictionary<int, string> filteredConnections = Handler.ConnectionFilter(filteredTelemetry);
                            foreach (KeyValuePair<int, string> item in filteredConnections)
                            {
                                //Console.WriteLine(item.Substring(0, item.LastIndexOf(',')));
                                string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                                var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                connectioneTable.AddRow(item.Key, value[0], value[1]);
                            }
                            if (filteredConnections.Count > 0)
                            {
                                Console.WriteLine("Connection Info: ");
                                connectioneTable.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                            }
                            //else
                            //{
                            //    Console.WriteLine("No Connection related infomation to display.");
                            //}
                        }

                        // Show all info
                        var verboseTable = new ConsoleTable("Line", "Info", "Value");
                        if (Handler.EventFilter(filteredTelemetry.EventName, "MIP_VerboseTelemetry"))
                        {

                            verboseTable.AddRow("", "Event name: ", filteredTelemetry.EventName);
                            verboseTable.AddRow("", "Event Time: ", filteredTelemetry.EventTime.Trim());
                            verboseTable.AddRow("", "Process: ", telemetry.Process.Trim());
                            //table.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);

                            
                            foreach (KeyValuePair<int, string> item in filteredTelemetry.TelemetryList)
                            {
                                //Console.WriteLine(item.Substring(0, item.LastIndexOf(',')));
                                string keyPair = item.Value.Substring(0, item.Value.LastIndexOf(",")); //split key and vaule by colon to write to table
                                var value = keyPair.Trim().Split(new[] { ':' }, 2);
                                verboseTable.AddRow(item.Key, value[0], value[1]);
                            }

                            if (filteredTelemetry.TelemetryList.Count>0)
                            {
                                Console.WriteLine("Detailed Telemetry: ");
                                verboseTable.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                            }
                            

                        }
                    }
                    if (infoTable.Rows.Count > 0)
                    {
                        Console.WriteLine("\n++++++++{0}++++++++", "Useful Trace Table");
                        infoTable.Configure(o => o.NumberAlignment = Alignment.Right).Write(Format.Alternative);
                        
                    }
                    else if ((infoTable.Rows.Count <= 0) && (category != "audit"))
                    {
                        Console.WriteLine("No Specific Infomation to display.");
                    }

                    //event name not in DB. Dev test only
                    if (otherevent.Count > 0)
                    {
                        foreach (string name in otherevent)
                        {
                            Console.WriteLine("Event name: ", name);
                        }
                    }
                    //Console.WriteLine("Filtered Event: {0}", eventflag.ToString());
                    Console.WriteLine("");
                }
            }

            
            if (category == "telemetry")
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Telemetry Information End.");
            }
            else
            {
                Console.WriteLine("\n++++++++{0}++++++++", "Audit Information End.");
            }
            Console.WriteLine("");
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
                if (Handler.IsFiltered(item.Value, "MIP_TelemetryError_1") || Handler.IsFiltered(item.Value, "MIP_TelemetryError_2"))
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