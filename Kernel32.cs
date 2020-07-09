using System;
using System.Runtime.InteropServices;

namespace CfgPoc
{
	public static unsafe class Kernel32
	{
		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern UIntPtr VirtualAlloc(UIntPtr lpAddress, UIntPtr dwSize,
			AllocationType flAllocationType, MemoryProtection flProtect);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool VirtualProtect(UIntPtr lpAddress, UIntPtr dwSize,
			MemoryProtection flNewProtect, out MemoryProtection lpflOldProtect);

		[Flags]
		public enum AllocationType : uint
		{
			MEM_COMMIT = 0x00001000,
			MEM_RESERVE = 0x00002000,
			MEM_RESET = 0x00080000,
			MEM_RESET_UNDO = 0x1000000,
			MEM_LARGE_PAGES = 0x20000000,
			MEM_PHYSICAL = 0x00400000,
			MEM_TOP_DOWN = 0x00100000,
			MEM_WRITE_WATCH = 0x00200000
		}

		[Flags]
		public enum MemoryProtection : uint
		{
			EXECUTE = 0x10,
			EXECUTE_READ = 0x20,
			EXECUTE_READWRITE = 0x40,
			EXECUTE_WRITECOPY = 0x80,
			NOACCESS = 0x01,
			READONLY = 0x02,
			READWRITE = 0x04,
			WRITECOPY = 0x08,
			GUARD_Modifierflag = 0x100,
			NOCACHE_Modifierflag = 0x200,
			WRITECOMBINE_Modifierflag = 0x400
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern IntPtr CreateFileMapping(
			IntPtr hFile,
			IntPtr lpFileMappingAttributes,
			FileMapProtection flProtect,
			uint dwMaximumSizeHigh,
			uint dwMaximumSizeLow,
			string lpName);

		[Flags]
		public enum FileMapProtection : uint
		{
			PageReadonly = 0x02,
			PageReadWrite = 0x04,
			PageWriteCopy = 0x08,
			PageExecuteRead = 0x20,
			PageExecuteReadWrite = 0x40,
			SectionCommit = 0x8000000,
			SectionImage = 0x1000000,
			SectionNoCache = 0x10000000,
			SectionReserve = 0x4000000,
		}

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

		[DllImport("kernel32.dll")]
		public static extern IntPtr MapViewOfFileEx(IntPtr hFileMappingObject,
			FileMapAccessType dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow,
			UIntPtr dwNumberOfBytesToMap, IntPtr lpBaseAddress);

		[Flags]
		public enum FileMapAccessType : uint
		{
			Copy = 0x01,
			Write = 0x02,
			Read = 0x04,
			AllAccess = 0x08,
			Execute = 0x20,
		}

		public static readonly IntPtr INVALID_HANDLE_VALUE = (IntPtr)0xffffffffffffffffL;

		[StructLayout(LayoutKind.Sequential)]
		public struct MEMORY_BASIC_INFORMATION
		{
			public IntPtr BaseAddress;
			public IntPtr AllocationBase;
			public MemoryProtection AllocationProtect;
			public UIntPtr RegionSize;
			public StateEnum State;
			public MemoryProtection Protect;
			public TypeEnum Type;
		}
		public enum StateEnum : uint
		{
			MEM_COMMIT = 0x1000,
			MEM_FREE = 0x10000,
			MEM_RESERVE = 0x2000
		}

		public enum TypeEnum : uint
		{
			MEM_IMAGE = 0x1000000,
			MEM_MAPPED = 0x40000,
			MEM_PRIVATE = 0x20000
		}

		[DllImport("kernel32.dll")]
		public static extern UIntPtr VirtualQuery(UIntPtr lpAddress, MEMORY_BASIC_INFORMATION* lpBuffer, UIntPtr dwLength);

		[DllImport("kernel32.dll")]
		public static extern void AddVectoredExceptionHandler(uint FirstHandler, UIntPtr VectoredHandler);
	}
}
