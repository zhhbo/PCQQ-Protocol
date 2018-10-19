using System;
using System.Runtime.InteropServices;

namespace QQ.Framework.Utils
{
    /// <summary>
    ///     ECDH操作类
    /// </summary>
    public class ECDHCrypter
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate IntPtr ECDH_KDF([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)]
            byte[] pin, int inlen, IntPtr pout, ref int outlen);

        public static bool HasInited;

        static ECDHCrypter()
        {
            try
            {
                var value = EC_KEY_new_by_curve_name(711);
                if (value != IntPtr.Zero)
                {
                    HasInited = true;
                }
            }
            catch
            {
                HasInited = false;
            }
        }

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EC_KEY_new_by_curve_name(int nid);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EC_KEY_get0_group(IntPtr key);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EC_POINT_new(IntPtr group);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern int EC_KEY_generate_key(IntPtr key);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr EC_KEY_get0_public_key(IntPtr key);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern void EC_KEY_free(IntPtr key);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern void EC_GROUP_free(IntPtr group);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern int ECDH_compute_key(byte[] pout, int outlen, IntPtr pub_key, IntPtr ecdh, ECDH_KDF kdf);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern int EC_POINT_point2oct(IntPtr group, IntPtr p, int form, byte[] buf, int len, IntPtr ctx);

        [DllImport("libeay32", CallingConvention = CallingConvention.Cdecl)]
        public static extern int EC_POINT_oct2point(IntPtr group, IntPtr p, byte[] buf, int len, IntPtr ctx);

        public static ECDH_struct GenKeys(int curveID)
        {
            var result = default(ECDH_struct);
            try
            {
                if (curveID <= 0 || curveID == 711)
                {
                    byte[] array =
                    {
                        0x04, 0x92, 0x8D, 0x88, 0x50, 0x67, 0x30, 0x88, 0xB3, 0x43,
                        0x26, 0x4E, 0x0C, 0x6B, 0xAC, 0xB8, 0x49, 0x6D, 0x69, 0x77,
                        0x99, 0xF3, 0x72, 0x11, 0xDE, 0xB2, 0x5B, 0xB7, 0x39, 0x06,
                        0xCB, 0x08, 0x9F, 0xEA, 0x96, 0x39, 0xB4, 0xE0, 0x26, 0x04,
                        0x98, 0xB5, 0x1A, 0x99, 0x2D, 0x50, 0x81, 0x3D, 0xA8
                    };
                    var array2 = new byte[25];
                    var array3 = new byte[16];
                    var intPtr = EC_KEY_new_by_curve_name(711);
                    if (intPtr != IntPtr.Zero)
                    {
                        var intPtr2 = EC_KEY_get0_group(intPtr);
                        if (intPtr2 != IntPtr.Zero)
                        {
                            var intPtr3 = EC_POINT_new(intPtr2);
                            if (EC_KEY_generate_key(intPtr) == 1)
                            {
                                var p = EC_KEY_get0_public_key(intPtr);
                                var num = EC_POINT_point2oct(intPtr2, p, 2, array2, 64, IntPtr.Zero);
                                var num2 = EC_POINT_oct2point(intPtr2, intPtr3, array, array.Length, IntPtr.Zero);
                                if (num2 == 1)
                                {
                                    num = ECDH_compute_key(array3, 64, intPtr3, intPtr, null);
                                    if (num > 0)
                                    {
                                        result.EC_publickey = array2;
                                        result.EC_sharekey = array3;
                                    }
                                }
                            }
                        }

                        EC_GROUP_free(intPtr2);
                    }
                }
            }
            catch
            {
            }

            return result;
        }
    }

    public struct ECDH_struct
    {
        public byte[] EC_publickey { get; set; }

        public byte[] EC_sharekey { get; set; }
    }
}