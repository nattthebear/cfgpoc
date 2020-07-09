using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using static CfgPoc.Kernel32;

namespace CfgPoc
{
	public class Program
	{
		/*
			mov r8, rsp
			mov rsp, rcx
			mov rax, [rdx + 8]
			mov rsp, r8
			ret
		*/
		private static byte[] FaultingProgram = { 0x49, 0x89, 0xE0, 0x48, 0x89, 0xCC, 0x48, 0x8B, 0x42, 0x08, 0x4C, 0x89, 0xC4, 0xC3 };

		/*
			mov rcx, [rcx] # PEXCEPTION_RECORD
			mov rdx, [rcx + 16] # EXCEPTION_ADDRESS
			mov rax, 0xdeadbeeffeedface
			cmp rdx, rax
			je good
			mov rax, 0 # EXCEPTION_CONTINUE_SEARCH
			ret
			good:
			mov rax, -1 #  EXCEPTION_CONTINUE_EXECUTION
			ret
		*/
		private static byte[] VehHandler = { 0x48, 0x8B, 0x09, 0x48, 0x8B, 0x51, 0x10, 0x48, 0xB8, 0xCE, 0xFA, 0xED, 0xFE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x39, 0xC2, 0x74, 0x08, 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3 };

		private static byte[] AwesomeDataToRead = { 0xed, 0x5f, 0x84 };

		private static void Copy(byte[] src, UIntPtr dest)
		{
			Marshal.Copy(src, 0, (IntPtr)(long)dest, src.Length);
		}

		private static void ReplaceConstant(byte[] data, ulong oldValue, UIntPtr newValue)
		{
			for (var i = 0; i < data.Length; i++)
			{
				if (data.Skip(i).Take(8).SequenceEqual(BitConverter.GetBytes(oldValue)))
				{
					for (var j = 0; j < 8; j++)
					{
						data[i + j] = BitConverter.GetBytes((ulong)newValue)[j];
					}
					return;
				}
			}
			throw new Exception();
		}

		private delegate long CallbackType(ulong rsp, UIntPtr dataAddress);

		public static unsafe int Main()
		{
			var awesomeDataBaseAddress = VirtualAlloc(UIntPtr.Zero, (UIntPtr)0x1000, AllocationType.MEM_COMMIT, MemoryProtection.READWRITE);

			var codeSpace = VirtualAlloc(UIntPtr.Zero, (UIntPtr)0x1000, AllocationType.MEM_COMMIT, MemoryProtection.EXECUTE_READWRITE);

			var stackSapce = VirtualAlloc(UIntPtr.Zero, (UIntPtr)(8ul << 20), AllocationType.MEM_COMMIT, MemoryProtection.READWRITE);

			var faultingProgramAddress = codeSpace;
			var vehHandlerAddress = codeSpace + 256;

			var rsp = (ulong)stackSapce + (8ul << 20);

			// When we read from awesomedata, we'll except
			// This read will happen with rip == 3 bytes before the 0x08
			ReplaceConstant(VehHandler, 0xdeadbeeffeedface, faultingProgramAddress + FaultingProgram.Select((b, i) => new { b, i }).First(a => a.b == 0x08).i - 3);

			Copy(FaultingProgram, faultingProgramAddress);
			Copy(VehHandler, vehHandlerAddress);
			Copy(AwesomeDataToRead, awesomeDataBaseAddress + 8);

			MemoryProtection old;
			// Set guard trip on the page containing awesomeData, so we'll get an exception
			VirtualProtect(awesomeDataBaseAddress, (UIntPtr)0x1000, MemoryProtection.READWRITE | MemoryProtection.GUARD_Modifierflag, out old);
			AddVectoredExceptionHandler(1, vehHandlerAddress);
			var ret = Marshal.GetDelegateForFunctionPointer<CallbackType>((IntPtr)(long)faultingProgramAddress)(rsp, awesomeDataBaseAddress);
			Console.WriteLine("Return from unmanaged code:" + ret);
			return 0;
		}
	}
}
