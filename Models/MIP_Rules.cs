using System;
using System.Collections.Generic;
using System.Text;

namespace SmallTool_MIP.Models
{
    public class MIP_Rules
    {
        // MIPMode 
        // 0 Invalid
        // 1 ErrorOnly
        // 2 Label & Policy
        // 3 trace : simple
        // 4 trace : verbose
        // 5 all -> give a report
        // 6 None

        public int MIPMode { get; set; }

        public bool Bootstrap { get; set; }

        public bool ErrorOnly { get; set; }

        public bool Label { get; set; }

        public string Trace { get; set; }

        public void Initialize()
        {
            switch (MIPMode)
            {
                //initialize rules
                case 1:
                    this.Bootstrap = true;
                    this.ErrorOnly = true;
                    this.Label = false;
                    this.Trace = null;
                    break;
                case 2:
                    this.Bootstrap = true;
                    this.ErrorOnly = false;
                    this.Label = true;
                    this.Trace = null;
                    break;
                case 3:
                    this.Bootstrap = true;
                    this.ErrorOnly = false;
                    this.Label = false;
                    this.Trace = "simple";
                    break;
                case 4:
                    this.Bootstrap = true;
                    this.ErrorOnly = false;
                    this.Label = false;
                    this.Trace = "verbose";
                    break;
                case 5:
                    this.Bootstrap = true;
                    this.ErrorOnly = true;
                    this.Label = true;
                    this.Trace = "simple";
                    break;
                case 6:
                    this.Bootstrap = true;
                    this.ErrorOnly = false;
                    this.Label = false;
                    this.Trace = null;
                    break;
                default:
                    this.MIPMode = 0;
                    break;
            }
        }
    }
}
