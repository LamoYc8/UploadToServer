package com.nyit.UploadToServer;

/**
 * Created by apple on 7/20/17.
 */

public class lea128 {
    int lea_num_rnds = 24;
    int lea_key__byte_len = 16;

    int RoR(int w, int i) {
        w = (w >> i) | (w << 32 - i);
        return w;
    }

    int RoL(int w, int i) {
        w = (w << i) | (w >> 32 - i);
        return w;
    }

    int[][] LEA_Keyschedule(int[][] pdRndKeys, byte[] pbKey) {
        int[] delta = new int[4];
        delta[0] = 0xc3efe9db;
        delta[1] = 0x44626b02;
        delta[2] = 0x79e27c8a;
        delta[3] = 0x78df30ec;
        int[] T = new int[4];

        T[0] = pbKey[0];
        T[1] = pbKey[4];
        T[2] = pbKey[8];
        T[3] = pbKey[12];
        for (int i = 0; i < lea_num_rnds; i++) {
            T[0] = RoL(T[0] + RoL(delta[i & 3], i), 1);
            T[1] = RoL(T[1] + RoL(delta[i & 3], i + 1), 3);
            T[2] = RoL(T[2] + RoL(delta[i & 3], i + 2), 6);
            T[3] = RoL(T[3] + RoL(delta[i & 3], i + 3), 11);

            pdRndKeys[i][0] = T[0];
            pdRndKeys[i][1] = T[1];
            pdRndKeys[i][2] = T[2];
            pdRndKeys[i][3] = T[1];
            pdRndKeys[i][4] = T[3];
            pdRndKeys[i][5] = T[1];
        }
        return pdRndKeys;
    }

    int[] LEA_EncryptBlk(int[] inputT, int[][] pdRndKeys) {
        int temp;

        int X0 = inputT[0];
        int X1 = inputT[1];
        int X2 = inputT[2];
        int X3 = inputT[3];

        for (int i = 0; i < lea_num_rnds; i++) {
            X3 = RoR((X2 ^ pdRndKeys[i][4]) + (X3 ^ pdRndKeys[i][5]), 3);
            X2 = RoR((X1 ^ pdRndKeys[i][2]) + (X2 ^ pdRndKeys[i][3]), 5);
            X1 = RoL((X0 ^ pdRndKeys[i][0]) + (X1 ^ pdRndKeys[i][1]), 9);
            temp = X0;
            X0 = X1;
            X1 = X2;
            X2 = X3;
            X3 = temp;
        }
        int[] output = new int[4];
        output[0] = X0;
        output[1] = X1;
        output[2] = X2;
        output[3] = X3;

        return output;
    }

    public static int[] longToIntArray(long num) {
        int[] result = new int[2];
        result[0] = (int) (num >>> 32);// 取最高8位放到0下标
        result[1] = (int) (num );// 取最高8位放到0下标
        return result;
    }

    public static byte[] longToByteArray(long num) {
        byte[] result = new byte[8];
        result[0] = (byte) (num >>> 56);// 取最高8位放到0下标
        result[1] = (byte) (num >>> 48);// 取最高8位放到0下标
        result[2] = (byte) (num >>> 40);// 取最高8位放到0下标
        result[3] = (byte) (num >>> 32);// 取最高8位放到0下标
        result[4] = (byte) (num >>> 24);// 取最高8位放到0下标
        result[5] = (byte) (num >>> 16);// 取次高8为放到1下标
        result[6] = (byte) (num >>> 8); // 取次低8位放到2下标
        result[7] = (byte) (num); // 取最低8位放到3下标
        return result;
    }

    protected static byte[] combineBArray(byte[] s1, byte[]s2){
        byte[] result = new byte[s1.length+s2.length];
        System.arraycopy(s1,0,result,0,s1.length);
        System.arraycopy(s2,0,result,s1.length,s2.length);
        return result;
    }


    protected static int[] combineArray(int[] s1, int[]s2){
        int[] result = new int[s1.length+s2.length];
        System.arraycopy(s1,0,result,0,s1.length);
        System.arraycopy(s2,0,result,s1.length,s2.length);
        return result;
    }


    public static void main(String[] args) {
        long text1 = 0x6373656420737265L;
        long text2 = 0x6c6c657661727420L;
        long k1 = 0x0706050403020100L;
        long k2 = 0x0f0e0d0c0b0a0908L;

        int[] t1 = longToIntArray(text1);
        int[] t2 = longToIntArray(text2);
        byte[] key1 = longToByteArray(k1);
        byte[] key2 = longToByteArray(k2);

        byte[] pbKey = combineBArray(key1, key2);
        int[][] pdRndKeys = new int[24][16];

        for (short i : pbKey) {
            System.out.println(i);

        }
        System.out.println();
        int[] x = combineArray(t1, t2);

        for (int i : x) {
            System.out.println(i);

        }
        System.out.println();

        lea128 t = new lea128();
        t.LEA_Keyschedule(pdRndKeys,pbKey);
        int[] outcome = t.LEA_EncryptBlk(x,pdRndKeys);
        for (int i : outcome) {
            System.out.println(i);

        }


    }
}
