using System;
using System.Collections.Generic;
using System.Text;

namespace SmallTool_MIP.Models
{
    public class MIP_LogObject
    {
        public string Line { get; set; }
        public string Level { get; set; }
        public string Date { get; set; }
        public string Logger { get; set; }
        public string Process { get; set; }
        public string Message { get; set; }

        public int Duration { get; set; } //x
        public string StackTrace { get; set; }
        public string Exception { get; set; } //x
        public string ThreadId { get; set; }

        public string User { get; set; } //x

    }
}
