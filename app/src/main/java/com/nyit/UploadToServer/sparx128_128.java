package com.nyit.UploadToServer;


import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;

public class sparx128_128 {
    short N_STEPS = 8;
    short ROUNDS_PER_STEPS = 4;
    short N_BRANCHES = 4;
    short K_SIZE = 4;

    protected short RotateL(short x, short n) {
        int outcome = ((x) << (n)) | ((x) >> (16 - (n)));
        x = (short) outcome;
        return x;
    }

    protected void swap(short x, short y) {
        short tmp = x;
        x = y;
        y = tmp;
    }

    protected void A(short l, short r) {
        l = RotateL(l, (short) 9);
        l += r;
        r = RotateL(r, (short) 2);
        r ^= l;
    }

    protected void L_4(short[] x) {
        int tmp = x[0] ^ x[1] ^ x[2] ^ x[3];
        tmp = RotateL((short) tmp, (short) 8);

        x[4] ^= x[2] ^ tmp;
        x[5] ^= x[1] ^ tmp;
        x[6] ^= x[0] ^ tmp;
        x[7] ^= x[3] ^ tmp;

        swap(x[0], x[4]);
        swap(x[1], x[5]);
        swap(x[2], x[6]);
        swap(x[3], x[7]);
    }

    protected void K_perm_128_128(short[] k, short c) {
        short tmp_0, tmp_1, i;
    /* Misty-like transformation */
        A(k[0], k[1]);
        k[2] += k[0];
        k[3] += k[1];
        A(k[4], k[5]);
        k[6] += k[4];
        k[7] += k[5] + c;
    /* Branch rotation */
        tmp_0 = k[6];
        tmp_1 = k[7];
        for (i = 7; i >= 2; i--) {
            k[i] = k[i - 2];
        }
        k[0] = tmp_0;
        k[1] = tmp_1;
    }

    protected short[][] key_schedule(short[][] subkeys, short[] master_key) {
        int c, i;
        for (c = 0; c < (N_BRANCHES * N_STEPS + 1); c++) {
            for (i = 0; i < 2 * ROUNDS_PER_STEPS; i++) {
                subkeys[c][i] = master_key[i];
            }
            K_perm_128_128(master_key, (short) c++);
        }
        return subkeys;
    }

    protected short[] sparxEncrypt(short[] x, short[][] k) {
        int s, r, b;

        for (s = 0; s < N_STEPS; s++) {
            for (b = 0; b < N_BRANCHES; b++) {
                for (r = 0; r < ROUNDS_PER_STEPS; r++) {
                    x[2 * b] ^= k[N_BRANCHES * s + b][2 * r];
                    x[2 * b + 1] ^= k[N_BRANCHES * s + b][2 * r + 1];
                    A(x[2 * b], x[2 * b + 1]);
                }
            }
            L_4(x);
        }
        for (b = 0; b < N_BRANCHES; b++) {
            x[2 * b] ^= k[N_BRANCHES * N_STEPS][2 * b];
            x[2 * b + 1] ^= k[N_BRANCHES * N_STEPS][2 * b + 1];
        }

        return x;
    }

    public static short[] longToShortArray(long num) {
        short[] result = new short[4];
        result[0] = (short) (num >>> 48);// 取最高8位放到0下标
        result[1] = (short) (num >>> 32);// 取最高8位放到0下标
        result[2] = (short) (num >>> 16);// 取最高8位放到0下标
        result[3] = (short) (num );// 取最高8位放到0下标
        return result;
    }

    protected static short[] combineArray(short[] s1, short[]s2){
        short[] result = new short[s1.length+s2.length];
        System.arraycopy(s1,0,result,0,s1.length);
        System.arraycopy(s2,0,result,s1.length,s2.length);
        return result;
    }

    public static void main(String[] args) {
        long text1 = 0x6373656420737265L;
        long text2 = 0x6c6c657661727420L;
        long k1 = 0x0706050403020100L;
        long k2 = 0x0f0e0d0c0b0a0908L;

        short[] t1 = longToShortArray(text1);
        short[] t2 = longToShortArray(text2);
        short[] key1 = longToShortArray(k1);
        short[] key2 = longToShortArray(k2);

        short[][] key = new short[33][8];

        short[] master_k = combineArray(key1,key2);

        for (short i:master_k) {
            System.out.println(i);

        }
        System.out.println();
        short[] x = combineArray(t1, t2);

        for (short i:x) {
            System.out.println(i);

        }
        System.out.println();

        sparx128_128 t = new sparx128_128();
        t.key_schedule(key, master_k);
        short[] outcome = t.sparxEncrypt(x, key);
        for (short i:outcome) {
            System.out.println(i);

        }


 }
}