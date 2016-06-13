using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Management;
using System.Collections.Concurrent;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using static WebExPopupKiller.Native;

namespace WebExPopupKiller
{
    public partial class WebExPopupKiller : ServiceBase, IDisposable
    {
        private readonly ManagementEventWatcher watcher = new ManagementEventWatcher(); // WMI watcher for new processes
        private readonly BlockingCollection<int> newPidQ = new BlockingCollection<int>(); // Queue of processes to inspect
        private readonly CancellationTokenSource ctsStop = new CancellationTokenSource(); // Cancellation token for clean shutdown
        private readonly byte[] methodStart; // Start
        private readonly byte[] methodEnd = new byte[] { 0x5b, 0x5d, 0xc2, 0x04, 0x00 };



        public WebExPopupKiller()
        {
            InitializeComponent();
            try
            {
                methodStart = System.IO.File.ReadAllBytes(AppDomain.CurrentDomain.BaseDirectory + "\\MethodStart.bin");
            }
            catch (Exception)
            {
                LogError("Couldn't load MethodStart.bin!");
                throw;
            }
            
        }

        protected override void OnStart(string[] args)
        {
            var t = new Thread(pidQConsumer);
            t.Start();
            WqlEventQuery query = new WqlEventQuery("__InstanceCreationEvent", new TimeSpan(0, 0, 30), "TargetInstance isa \"Win32_Process\"");

            watcher.Query = query;
            watcher.EventArrived += new EventArrivedEventHandler(ProcessStartEvent);
            watcher.Start();
        }

        public void ProcessStartEvent(object sender, EventArrivedEventArgs e)
        {
            ManagementBaseObject newEvent = e.NewEvent;
            ManagementBaseObject process = (ManagementBaseObject)newEvent["TargetInstance"];
            int processId = (int)(uint)(process["ProcessId"]);
            newPidQ.Add(processId);
        }

        private void pidQConsumer()
        {
            while (true)
            {
                try
                {
                    var newPid = newPidQ.Take(ctsStop.Token);

                    using (var process = Process.GetProcessById(newPid))
                    {

                        // If this is the WebEx process
                        if (process.ProcessName == "atmgr")
                        {
                            // Find the webexmgr module
                            var webexmgr = process.Modules.Cast<ProcessModule>().FirstOrDefault(m => m.ModuleName == "webexmgr.dll");

                            if (webexmgr == null)
                            {                                
                                LogError("I found the webex (atmgr) process, but I couldn't locate the webexmgr.dll module!");
                                continue;
                            }

                            using (var processHandle = OpenProcess(
                                ProcessAccessFlags.QueryInformation |
                                ProcessAccessFlags.VirtualMemoryRead |
                                ProcessAccessFlags.VirtualMemoryWrite |
                                ProcessAccessFlags.VirtualMemoryOperation,
                                false, process.Id))
                            {
                                // Copy the module so we can look at it easier
                                byte[] buffer = new byte[webexmgr.ModuleMemorySize];

                                int bytesRead = 0;
                                if (!ReadProcessMemory((int)processHandle.DangerousGetHandle(), (int)webexmgr.BaseAddress, buffer, webexmgr.ModuleMemorySize, ref bytesRead))
                                {
                                    LogError("I found the webexmgr.dll module, but I couldn't read its memory!");
                                    continue;
                                }

                                // Locate the start of the block we need to wipe out
                                var startAddress = IndexOf(buffer, methodStart) - 5;

                                if (startAddress == -1)
                                {
                                    LogError("I found the webexmgr.dll module, but I couldn't find the start of the method to wipe out!");
                                    continue;
                                }

                                // Locate the end of the block we need to wipe out
                                var endAddress = IndexOf(buffer, methodEnd, startAddress + methodStart.Length);

                                if (endAddress == -1)
                                {
                                    LogError("I found the webexmgr.dll module and the start of the method to wipe out, but I couldn't find the end of it!");
                                    continue;
                                }

                                // Generate a patch of the appropriate length
                                var patch = new byte[endAddress - startAddress];
                                for (int i = 0; i < patch.Length; i++)
                                {
                                    patch[i] = 0x90;
                                }

                                // Calculate the absolute start address
                                var absoluteStartAddress = webexmgr.BaseAddress + startAddress;

                                // Apply the patch
                                int bytesWritten = 0;
                                var written = WriteProcessMemory((int)processHandle.DangerousGetHandle(), (int)absoluteStartAddress, patch, patch.Length, ref bytesWritten);

                                if (!written || bytesWritten != patch.Length)
                                {
                                    LogError("I found the memory to patch, but I couldn't write the data!");
                                    continue;
                                }

                                LogInfo("I successfully patched WebEx!");
                            }
                        }
                    }

                }
                catch (InvalidOperationException)
                {
                    return;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ArgumentException)
                {
                    continue;
                }
                catch (Exception ex)
                {
                    LogError(ex.ToString());
                }

            }

        }

        private static int IndexOf(byte[] source, byte[] search, int start = 0)
        {
            var len = search.Length;

            for (var outer = start; outer <= source.Length - search.Length; outer++)
            {
                int inner;
                for (inner = 0; inner < len; inner++)
                {
                    if (search[inner] != source[outer + inner]) break;
                }
                if (inner == search.Length) return outer;
            }
            return -1;
        }


        private static void LogInfo(string message)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "WebExPopupKiller";
                eventLog.WriteEntry(message, EventLogEntryType.Information, 0, 1);
            }
        }

        private static void LogError(string message)
        {
            using (EventLog eventLog = new EventLog("Application"))
            {
                eventLog.Source = "WebExPopupKiller";
                eventLog.WriteEntry(message, EventLogEntryType.Warning, 0, 1);
            }
        }

        protected override void OnStop()
        {
            watcher.Stop();
            newPidQ.CompleteAdding();
        }

        public new void Dispose()
        {
            watcher.Dispose();
            newPidQ.Dispose();
            ctsStop.Dispose();

            base.Dispose();
        }
    }
}
