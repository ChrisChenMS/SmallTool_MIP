using System;
using System.Collections.Generic;
using System.Text;

namespace SmallTool_MIP.Models
{
    public class MIP_TelemetryObject
    {
        public string ThreadId { get; set; }
        public string Process { get; set; }
        public string EventTime { get; set; }
        public string EventName { get; set; }
        public Dictionary<int, string> TelemetryList { get; set; }
    }
}
