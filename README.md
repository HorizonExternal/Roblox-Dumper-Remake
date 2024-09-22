
# Roblox-Dumper
Roblox-Dumper is a tool designed to dump a process (Mainly for roblox, hyperion)

# How it works
The dumper works by loading functions from ntdll.dll. It then queries the process (which is specified at the start of the class by setting the process name) and retrieves the process ID. Afterward, it uses NtOpenProcess to open the game or whatever you're dumping. It gets more detailed information about the process using the GetModuleInfo() function (which is included in the code). Once it gets all the data, it dumps the process memory and saves it to disk. The path can be changed at the start of the class.

# Usage
Make sure the target process (in this case, Roblox) is running.
Run the dumper (preferably as admin to avoid permission issues).
Ensure anti virus is disabled.
Once ran, the dumper will save the process dump to the path you specified (by default, it saves to the same folder as the executable).
After getting the dump, you can use IDA or another app to analyze the dump.


# Credits
Blizex - Development of the dumper.
Atrexus - Original idea and creation [Github](https://github.com/atrexus/vulkan/).
