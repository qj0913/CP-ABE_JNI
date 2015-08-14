package edu.ncepu.abe;

import java.nio.ByteBuffer;

public class CP_ABE
{
    static {
        System.loadLibrary("CPABE");
    };
    public static native ByteBuffer setup();
    public static native ByteBuffer encrypt(byte[] pubkey,String policy,String key);
    public static native ByteBuffer kengen(byte[] pubkey,byte[] mskkey,String[] attrs);
    public static native String decrypt(byte[] pubkey,byte[] prvkey,byte[] cphtext);
}
