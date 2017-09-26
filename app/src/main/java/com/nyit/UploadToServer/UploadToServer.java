package com.nyit.UploadToServer;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.app.ProgressDialog;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.util.Base64;
import android.util.Log; //日志工具类，可以打印日志
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.RadioGroup.OnCheckedChangeListener;
import android.widget.TextView;
import android.widget.Toast;


public class UploadToServer extends Activity {

	TextView messageText;
	EditText userInput, etIPAddress;
	Button uploadButton, AutoSendButton, encrypt;
//	Toast reaction "make text" is available
	RadioButton rb100, rb500, rb1000, rb1500, rb2000, rb2500, 
		rbAES, rbBlowfish, rbShift, rbRC4, rbSimon128, rbSpeck128, rbSparx128, rbLea128;
//	4 new variables;
//	select one from file size and one from encryption based on the menu
	RadioGroup rgEncryption;

	int keyLength;
	int serverResponseCode = 0;
	ProgressDialog dialog = null;
	BufferedReader reader = null;
	FileWriter fos;
	String upLoadServerUri, uploadFileName, line, encType, result,
			fileName = null;
	static final String TAG = "SymmetricAlgorithm";
	SecretKeySpec sks = null;
	SecureRandom sr = null;
	KeyGenerator kg = null;
	byte[] encodedBytes = null;
	byte [] z ={1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1};



	/********** File Path *************/
//	String uploadFilePath = "/sdcard/Download/";
	String uploadFilePath = "/storage/emulated/0/";

	@Override
	public void onCreate(Bundle savedInstanceState) { // = public void static main

		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_upload_to_server);
		initializeVariables();
//		from this method, it can combine the logic variables which are defined above with all the practical items in the layout
		messageText.setText("Uploading file path :- " + uploadFilePath);
		// ListSupportedAlgorithms();
		// messageText.setText(result);

		uploadButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				checkFile();
				String[] toSend = { uploadFileName };
				Launch(toSend);
			}
		});

		rgEncryption.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(RadioGroup group, int checkedId) {
				switch (checkedId) {
					case R.id.rbAES:
						encType = "AES";
						break;

					case R.id.rbShift:
						encType = "Shift";
						break;

					case R.id.rbBlowfish:
						encType = "Blowfish";
						break;

					case R.id.rbRC4:
						encType = "RC4";
						break;

					case R.id.rbSimon128:
						encType = "Simon128";
						break;

					case R.id.rbSpeck128:
						encType = "Speck128";
						break;

					case R.id.rbSparx128:
						encType = "SparX128";
						break;

					case R.id.rbLea128:
						encType = "LEA128";
						break;
				}
				userInput.setHint("Enter " + encType + " Key Length");
			}
		});

		encrypt.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v) {
				checkFile();
				try {
					fileName = "encrypted" + encType + uploadFileName;
					File myFile = new File(Environment
							.getExternalStorageDirectory(), fileName);
					if (!myFile.exists()) {
						myFile.createNewFile();
					}
					fos = new FileWriter(myFile);
					reader = new BufferedReader(new FileReader(""
							+ uploadFilePath + uploadFileName));
				} catch (FileNotFoundException e) {
					e.printStackTrace();
					Log.e(TAG,"No such file");
				} catch (IOException e) {
					e.printStackTrace();
					Log.e(TAG,"Reader or Writer has errors");
				}
//				判断选择的加密的算法
				if (rbShift.isChecked()) {
					try {
						while ((line = reader.readLine()) != null) {
							shiftEncrypt();

						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				else if (rbSimon128.isChecked()) {
					try {
						while ((line = reader.readLine()) != null) {
							simon128En();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}

				}
				else if (rbSpeck128.isChecked()){
					try {
						while ((line = reader.readLine()) != null) {
							speck128En();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				else if (rbSparx128.isChecked()){
					try {
						while ((line = reader.readLine()) != null) {
							sparX128En();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				else if (rbLea128.isChecked()) {
					try {
						while ((line = reader.readLine()) != null) {
							Lea128En();
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				else{
					if (userInput.getText().toString().isEmpty()) {
						keyLength = 128;
					} else {
						keyLength = Integer.parseInt((userInput.getText()
								.toString()));
					}
					try {
						sr = SecureRandom.getInstance("SHA1PRNG");
						sr.setSeed("any data used as random seed".getBytes());
						kg = KeyGenerator.getInstance(encType);
//						选择剩下除 Shift 之外的三个加密算法
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
					}
					kg.init(keyLength, sr);
					sks = new SecretKeySpec((kg.generateKey()).getEncoded(),
							encType);
					try {
						while ((line = reader.readLine()) != null) {
							encrypt();
//							完成加密
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
					}
				try {
					fos.flush();
					fos.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		});
	}

	private void ListSupportedAlgorithms() {
		result = "";
		Provider[] providers = Security.getProviders();
		for (int p = 0; p < providers.length; p++) {
			// get all service types for a specific provider
			Set<Object> ks = providers[p].keySet();
			Set<String> servicetypes = new TreeSet<String>();
			for (Iterator<Object> it = ks.iterator(); it.hasNext();) {
				String k = it.next().toString();
				k = k.split(" ")[0];
				if (k.startsWith("Alg.Alias."))
					k = k.substring(10);
				servicetypes.add(k.substring(0, k.indexOf('.')));
			}
			// get all algorithms for a specific service type
			int s = 1;
			for (Iterator<String> its = servicetypes.iterator(); its.hasNext();) {
				String stype = its.next();
				Set<String> algorithms = new TreeSet<String>();
				for (Iterator<Object> it = ks.iterator(); it.hasNext();) {
					String k = it.next().toString();
					k = k.split(" ")[0];
					if (k.startsWith(stype + "."))
						algorithms.add(k.substring(stype.length() + 1));
					else if (k.startsWith("Alg.Alias." + stype + "."))
						algorithms.add(k.substring(stype.length() + 11));
				}

				int a = 1;
				for (Iterator<String> ita = algorithms.iterator(); ita
						.hasNext();) {
					result += ("[P#" + (p + 1) + ":" + providers[p].getName()
							+ "]" + "[S#" + s + ":" + stype + "]" + "[A#" + a
							+ ":" + ita.next() + "]\n");
					a++;
				}
				s++;
			}
		}
	}

	protected void simon128En(){
		String line2="";
		long[] inputK = new long[2];
		byte[] secretK = this.keyGeneration();
//		把 key 产生的过程放入 function keyGeneration 之中


		ByteBuffer buffer = ByteBuffer.allocate(8);
		for(int j= 0; j<secretK.length/8; j++)
		{
			buffer.put(secretK, j*8, 8);
			buffer.flip();//need flip
			inputK[j] = buffer.getLong();
			buffer.clear();
		}

		//		modify the plaintext
		line = line.toLowerCase();
		line = line.replaceAll("[^a-zA-Z ]+", "");
		byte[] plainText = line.getBytes();
		double denominator = 8;
		int count = (int)Math.ceil(plainText.length/denominator);
		long[] modifiedT = new long[count];

		for(int i = 0; i<count; i++)
		{
			int remain = plainText.length-i*8;
			if ((remain<8)&&(remain>0)){

				buffer.put(plainText, i*8, remain);
				buffer.rewind();//need rewind
//				rewind 和 flip 作用类似方便接下去的get或者 read ，flip会将 limit 设为当前 buffer 中的 position(<capacity),但 rewind 不会动 limit 的位置
				modifiedT[i] = buffer.getLong();
				buffer.clear();
			}else{
				buffer.put(plainText, i*8, 8);
				buffer.flip();//need flip
				modifiedT[i] = buffer.getLong();
                buffer.clear();
//				set position to 0, set limit to capacity
			}
		}

		LinkedList<Long> inputT = new LinkedList<>();
		for(int i =0; i< count; i++){
			String encrypted;
			if((i==count-1)&&(count%2!=0)) {
				inputT.add(modifiedT[i]);
				long[] inputText = new long[2];
				inputText[0] = inputT.pollFirst();
				inputText[1] = 0;
				encrypted = simonEncrypt(inputText,inputK).toString();

			}else {
				inputT.add(modifiedT[i]);
				inputT.add(modifiedT[i+1]);
				i++;
				long[] inputText = new long[2];
				inputText[0] = inputT.pollFirst();
				inputText[1] = inputT.pollFirst();
				encrypted = simonEncrypt(inputText,inputK).toString();
			}
			line2 += encrypted;
		}

		try{
			fos.write(line2);
		}catch (IOException e){
			e.printStackTrace();
		}

	}

	protected void speck128En(){
		//create a key with length of 128bits
		String line2="";
		keyLength = 128;
		String keyWords = userInput.getText().toString();
		long[] inputK = new long[2];
		try {
			sr  = new SecureRandom();
			sr.setSeed(keyWords.getBytes());
			kg = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		kg.init(keyLength, sr);
		byte[] secretK = kg.generateKey().getEncoded();
//			getEncoded() 是 key 类，专用

		ByteBuffer buffer = ByteBuffer.allocate(8);
		for(int j= 0; j<secretK.length/8; j++)
		{
			buffer.put(secretK, j*8, 8);
			buffer.flip();//need flip
			inputK[j] = buffer.getLong();
			buffer.clear();
		}

		//		modify the plaintext
		line = line.toLowerCase();
		line = line.replaceAll("[^a-zA-Z ]+", "");
		byte[] plainText = line.getBytes();
		double denominator = 8;
		int count = (int)Math.ceil(plainText.length/denominator);
		long[] modifiedT = new long[count];
		for(int i = 0; i<count; i++)
		{
			ByteBuffer bufferT = ByteBuffer.allocate(8);
			int remain = plainText.length-i*8;
			if ((remain<8)&&(remain>0)){

				bufferT.put(plainText, i*8, remain);
				bufferT.rewind();//need rewind
//				rewind 和 flip 作用类似方便接下去的get或者 read ，flip会将 limit 设为当前 buffer 中的 position(<capacity),但 rewind 不会动 limit 的位置
				modifiedT[i] = bufferT.getLong();
			}else{
				bufferT.put(plainText, i*8, 8);
				bufferT.flip();//need flip
				modifiedT[i] = bufferT.getLong();
//                buffer.clear(); set position to 0, set limit to capacity
			}

		}
		LinkedList<Long> inputT = new LinkedList<>();
		for(int i =0; i< count; i++){
			String encrypted;
			if((i==count-1)&&(count%2!=0)) {
				inputT.add(modifiedT[i]);
				long[] inputText = new long[2];
				inputText[0] = inputT.pollFirst();
				inputText[1] = 0;
				encrypted = speckEncrypt(inputText,inputK).toString();

			}else {
				inputT.add(modifiedT[i]);
				inputT.add(modifiedT[i+1]);
				i++;
				long[] inputText = new long[2];
				inputText[0] = inputT.pollFirst();
				inputText[1] = inputT.pollFirst();
//				simonEncrypt(inputText,inputK);
				encrypted = speckEncrypt(inputText,inputK).toString();
			}
			line2 += encrypted;
		}

		try{
			fos.write(line2);
		}catch (IOException e){
			e.printStackTrace();
		}

	}

	protected void sparX128En(){
		String line2="";
		byte[] keyG = keyGeneration();
		ByteBuffer bufferS = ByteBuffer.allocate(16);
		short[] masterK = new short[8];
		short[][] k = new short[33][8];
		sparx128_128 s= new sparx128_128();
//		instantiate class sparx128_128
		for(int i=0; i<keyG.length/2; i++){
			bufferS.put(keyG,i*2,2);
			bufferS.flip();
			masterK[i] = bufferS.getShort();
			bufferS.clear();
		}
		k =s.key_schedule(k, masterK);


		//		modify the plaintext
		line = line.toLowerCase();
		line = line.replaceAll("[^a-zA-Z ]+", "");
		byte[] plainText = line.getBytes();
		double denominator = 2;
		int count = (int)Math.ceil(plainText.length/denominator);
		short[] modifiedT = new short[count];
		for(int i = 0; i<count; i++)
		{
			int remain = plainText.length-i*2;
			if ((remain<2)&&(remain>0)){
				bufferS.put(plainText, i*2, remain);
				bufferS.rewind();//need rewind
//				rewind 和 flip 作用类似方便接下去的get或者 read ，flip会将 limit 设为当前 buffer 中的 position(<capacity),但 rewind 不会动 limit 的位置
				modifiedT[i] = bufferS.getShort();
				bufferS.clear();
			}else{
				bufferS.put(plainText, i*2, 2);
				bufferS.flip();//need flip
				modifiedT[i] = bufferS.getShort();
                bufferS.clear();
			}
		}

		//linkedList holds the entire short array modified plaintext and then starts encrypting.
		LinkedList<Short> inputT = new LinkedList<>();
		for(int i= 0; i<modifiedT.length; i++){
			inputT.add(modifiedT[i]);
		}

		while(!inputT.isEmpty()){

			short[] inputText ={0,0,0,0,0,0,0,0};
			if(inputT.size()<8){
				for(int j= 0; j<inputT.size(); j++){
					inputText[j]=inputT.pollFirst();
				}
			} else {
				for(int j= 0; j<8; j++)
			{
				inputText[j]=inputT.pollFirst();
			}

			}
			line2 += s.sparxEncrypt(inputText,k).toString();
		}


		//	write the output into the file
		try{
			fos.write(line2);
		}catch (IOException e){
			e.printStackTrace();
		}
	}

	protected void Lea128En(){
		String line2="";
		byte[] pbKey = keyGeneration();
		ByteBuffer bufferL = ByteBuffer.allocate(4);
		int[][] pdRndKeys = new int[24][16];
		lea128 l = new lea128();
//		instantiate class lea128

		pdRndKeys =l.LEA_Keyschedule(pdRndKeys,pbKey);

		//		modify the plaintext
		line = line.toLowerCase();
		line = line.replaceAll("[^a-zA-Z ]+", "");
		byte[] plainText = line.getBytes();
		double denominator = 4;
		int count = (int)Math.ceil(plainText.length/denominator);
		int[] modifiedT = new int[count];

		for(int i = 0; i<count; i++)
		{
			int remain = plainText.length-i*4;
			if (remain<4&&remain>0){
				bufferL.put(plainText, i*4, remain);
				bufferL.rewind();//need rewind
//				rewind 和 flip 作用类似方便接下去的get或者 read ，flip会将 limit 设为当前 buffer 中的 position(<capacity),但 rewind 不会动 limit 的位置
				modifiedT[i] = bufferL.getInt();
			}else{
				bufferL.put(plainText, i*4, 4);
				bufferL.flip();//need flip
				modifiedT[i] = bufferL.getInt();
				bufferL.clear();
			}
		}

		//linkedList holds the entire short array modified plaintext and then starts encrypting.
		LinkedList<Integer> inputT = new LinkedList<>();
		for(int i= 0; i<modifiedT.length; i++){
			inputT.add(modifiedT[i]);
		}

		while(!inputT.isEmpty()){
			int[] inputText ={0,0,0,0};
			if(inputT.size()<4){
				for(int j= 0; j<inputT.size(); j++){
					inputText[j]=inputT.pollFirst();
				}
			} else {
				for(int j= 0; j<4; j++)
				{
					inputText[j]=inputT.pollFirst();
				}

			}
			line2 += l.LEA_EncryptBlk(inputText, pdRndKeys);

		}

		//	write the output into the file
		try{
			fos.write(line2);
		}catch (IOException e){
			e.printStackTrace();
		}



	}

	protected byte[] keyGeneration(){

		//create a key with length of 128bits
		keyLength = 128;
		String keyWords = userInput.getText().toString();
		try {
			sr  = new SecureRandom();
			sr.setSeed(keyWords.getBytes());
			kg = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		kg.init(keyLength, sr);
		byte[] key = kg.generateKey().getEncoded();
//			getEncoded() 是 key 类，专用
		return key;
	}

	protected long rotateRight64(long x, long n){
		long outcome = (((x) >> (n)) | ((x) << (64-(n))));
		return outcome;
	}

	protected long rotateLeft64(long x, long n){
		long outcome =  ((x) << (n)) | ((x) >> (64-(n)));
		return outcome;
	}


	protected long[] simonKeyExpansion(long[] key){
		long tmp;
		long[] k = new long[68];
		k[0] = key[0];
		k[1]= key[1];
		for(int i = 2; i<68;i++)
		{
			k[i] = 0;
		}
		for (int i = 2; i<64;i++ ){
			tmp = rotateRight64(k[i-1], 3);
			tmp = tmp ^ rotateRight64(tmp, 1);
			k[i] = ~k[i-2] ^ tmp ^ z[(i-2)]^3;
		}

		for(int i= 64; i<68; i++){
			tmp = rotateRight64(k[i-1],3);
			tmp = tmp ^ rotateRight64(tmp, 1);
			k[i]= ~k[i-2] ^ tmp ^ z[(i-2)-62]^3;
		}
		return k;
	}

	protected long[] simonEncrypt(long[] text, long[] key){
		key = simonKeyExpansion(key);
		long tmp;
		long[] crypt = new long[2];
		crypt[0]= text[0];
		crypt[1]= text[1];
		for(int i=0; i<68; i++){
			tmp = crypt[0];
			crypt[0] = crypt[1]^((rotateLeft64(crypt[0],1)) & (rotateLeft64(crypt[0],8))) ^ (rotateLeft64(crypt[0],2))^key[i];
			crypt[1] = tmp;
		}

		return crypt;
	}

	protected long[] speckKeyExpansion(long[] key){
		long[] k = new long[32];
		long[] l = new long[32];
		k[0]=key[0];
		l[0]=key[1];
		for (int i=0 ; i<31 ; i++ )
		{
			l[i+1] = ( k[i] + rotateRight64(l[i], 8) ) ^ i;
			k[i+1] = rotateLeft64(k[i], 3) ^ l[i+1];
		}
		return k;
	}

	protected long[] speckEncrypt(long[] text, long[] key){
		key = speckKeyExpansion(key);
		long[] crypt = new long[2];
		crypt[0] = text[0];
		crypt[1] = text[1];

		for (int i=0 ; i<32 ; i++ )
		{
			crypt[0] = ( rotateRight64(crypt[0], 8) + crypt[1] ) ^ key[i];
			crypt[1] = rotateLeft64(crypt[1], 3) ^ crypt[0];
		}
		return crypt;
	}


	protected void encrypt() {
		try {
			Cipher c = Cipher.getInstance(encType);
			c.init(Cipher.ENCRYPT_MODE, sks);
			encodedBytes = c.doFinal(line.getBytes());
//			译成密码的位
			String output = Base64.encodeToString(encodedBytes, Base64.DEFAULT);
			fos.write(output);
		} catch (Exception e) {
			Log.e(TAG, encType + " secret key spec error");
		}
	}

	protected void shiftEncrypt() {
		String line2 = "";
		int key;

		line = line.toLowerCase();
		// removes all special characters and numbers from the user's input to
		// make encryption harder to hack
		// --To leave spaces between the words just leave a space after A-Z
		line = line.replaceAll("[^a-zA-Z ]+", ""); //replacing all occurrences of "[^a-zA-Z] to ""
		try {
			key = Integer.parseInt(userInput.getText().toString());
			if ((key >= -25) && (key <= 25)) {
				char[] chars = line.toCharArray();

				for (int i = 0; i < line.length(); i++) {
					char c = chars[i];
					char encrypted = sEncrypt(c, key);
					String output = Character.toString(encrypted);
					line2 += output;// ENCRYPTED INPUT IS DISPLAYED HERE
				}// end outside FOR LOOP
				fos.write(line2);
			} else {
				Toast.makeText(getApplicationContext(),
						"Key must be between 0 and 25!", Toast.LENGTH_LONG)
						.show();
				key = Integer.parseInt(String.valueOf(userInput));
			}
		}// end try
		catch (NumberFormatException h) {
			Toast.makeText(getApplicationContext(),
					"Key must be between 0 and 25!", Toast.LENGTH_LONG).show();
		} catch (Exception j) {
			Toast.makeText(getApplicationContext(),
					"Key must be between 0 and 25!", Toast.LENGTH_LONG).show();
		}
	}// END EncryptButtonHandler

	char sEncrypt(char c, int key) {
		char[] alphabet = new char[26];
		int i = 0;
		// fills alphabet array with the alphabet
		for (char ch = 'a'; ch <= 'z'; ++ch) {
			alphabet[ch - 'a'] = ch;
		}
		/********************** BELOW CODE FROM: ***********************/
		// http://www.cs.utsa.edu/~wagner/laws/Acaesar.html
		while (i < 26) {
			if (c == alphabet[i])
				return alphabet[(i + key + 26) % 26];
			i++;
		}
		return c;
		/*************************************************************/
	}

	public void checkFile() {
		if (rb100.isChecked()) {
			uploadFileName = "100kB.txt";
		} else if (rb500.isChecked()) {
			uploadFileName = "500kB.txt";
		} else if (rb1000.isChecked()) {
			uploadFileName = "1000kB.txt";
		} else if (rb1500.isChecked()) {
			uploadFileName = "1500kB.txt";
		} else if (rb2000.isChecked()) {
			uploadFileName = "2000kB.txt";
		} else if (rb2500.isChecked()) {
			uploadFileName = "2500kB.txt";
		} else {
			Toast.makeText(UploadToServer.this, "No file selected.",
					Toast.LENGTH_SHORT).show();
		}
	}


	// combine the logic variables with the layout
	private void initializeVariables() {
		userInput = (EditText) findViewById(R.id.etKey);
		etIPAddress = (EditText) findViewById(R.id.etIPAddress);
		uploadButton = (Button) findViewById(R.id.uploadButton);
		encrypt = (Button) findViewById(R.id.btnEncrypt);
		messageText = (TextView) findViewById(R.id.messageText);
		rb100 = (RadioButton) findViewById(R.id.rb100);
		rb500 = (RadioButton) findViewById(R.id.rb500);
		rb1000 = (RadioButton) findViewById(R.id.rb1000);
		rb1500 = (RadioButton) findViewById(R.id.rb1500);
		rb2000 = (RadioButton) findViewById(R.id.rb2000);
		rb2500 = (RadioButton) findViewById(R.id.rb2500);
		rbAES = (RadioButton) findViewById(R.id.rbAES);
		rbBlowfish = (RadioButton) findViewById(R.id.rbBlowfish);
		rbShift = (RadioButton) findViewById(R.id.rbShift);
		rbRC4 = (RadioButton) findViewById(R.id.rbRC4);
		rgEncryption = (RadioGroup) findViewById(R.id.rgEncryption);
//		combining the logic variables with buttons in layout
		rbSimon128 = (RadioButton)findViewById(R.id.rbSimon128);
		rbSpeck128 = (RadioButton)findViewById(R.id.rbSpeck128);
		rbSparx128 = (RadioButton)findViewById(R.id.rbSparx128);
		rbLea128 =(RadioButton)findViewById(R.id.rbLea128);
	}

	public void Launch(final String[] fileNames) {
		dialog = ProgressDialog.show(UploadToServer.this, "",
				"Uploading file...", true);

		/*子线程对 UI 进行操作，原理基于异步消息处理机制
		* abstract class AsyncTask: three static arguments
		* Params:执行时需要传入的参数，可用于在后台任务使用
		* Progress: 后台任务执行中，显示在界面上的当前的进度的单位
		* Result: 完毕后，对结果进行返回的值 type */
		new AsyncTask<String, Integer, Void>() {

			protected Void doInBackground(String... fileNames) {
				int responseCode = 0;

				responseCode = uploadFile(uploadFilePath + "" + fileNames[0]);
				publishProgress(responseCode);
				return null;
				/*该方法中的代码于 sub-thread 中执行，其return 值则为上述参数中的 result
				* 该方法自身不可进行 UI 操作（例如：更新 UI 元素），必须调用 publishProgress(Progress...)来完成*/
			}

			protected void onProgressUpdate(Integer... progress) {
				/*publishProgress(Progress...)方法的后续
				* 所携带的参数由后台任务中传递而来
				* 在此方法中对 UI 进行操作，利用参数数值对界面元素进行更新*/
				switch (progress[0]) {
				case 0:
					break;
				case 200:
					String msg = "File Upload Completed.\n\n See uploaded file here : \n\n"
							+ upLoadServerUri + "/uploads/";
					messageText.setText(msg);
					Toast.makeText(UploadToServer.this,
							"File Upload Complete.", Toast.LENGTH_SHORT).show();
					break;
				}
			}

			protected void onPostExecute(Long result) {
				// showDialog("Downloaded " + result + " bytes");
			}
		}.execute(fileNames);
		/*doInBackground() 执行具体耗时任务
		* onProgressUpdate() 进行 UI 操作
		* onPostExecute() 收尾工作*/
	}

	public int uploadFile(String sourceFileUri) {
		String fileName = sourceFileUri;

		HttpURLConnection conn = null;
		DataOutputStream dos = null;
		String lineEnd = "\r\n";
		String twoHyphens = "--";
		String boundary = "*****";
		int bytesRead, bytesAvailable, bufferSize;
		byte[] buffer;
		int maxBufferSize = 1 * 1024 * 1024;
		File sourceFile = new File(sourceFileUri);

		if (!sourceFile.isFile()) {
			dialog.dismiss();
			Log.e("uploadFile", "Source File not exist :" + uploadFilePath + ""
					+ uploadFileName);
			runOnUiThread(new Runnable() {
				public void run() {
					messageText.setText("Source File not exist :"
							+ uploadFilePath + "" + uploadFileName);
				}
			});
			return 0;
		} else {
			try {
				// open a URL connection to the Servlet
				FileInputStream fileInputStream = new FileInputStream(
						sourceFile);
				if (etIPAddress.getText().toString().isEmpty()) {
					upLoadServerUri = "http://216.37.101.30/Uploads.php";
				} else {
					upLoadServerUri = "http://"
							+ etIPAddress.getText().toString()
							+ "/UploadToServer.php";
				}
				URL url = new URL(upLoadServerUri);

				// Open a HTTP connection to the URL
				conn = (HttpURLConnection) url.openConnection();
				conn.setDoInput(true); // Allow Inputs
				conn.setDoOutput(true); // Allow Outputs
				conn.setUseCaches(false); // Don't use a Cached Copy
				conn.setRequestMethod("POST");
				conn.setRequestProperty("Connection", "Keep-Alive");
				conn.setRequestProperty("ENCTYPE", "multipart/form-data");
				conn.setRequestProperty("Content-Type",
						"multipart/form-data;boundary=" + boundary);
				conn.setRequestProperty("uploaded_file", fileName);

				dos = new DataOutputStream(conn.getOutputStream());
				dos.writeBytes(twoHyphens + boundary + lineEnd);
				dos.writeBytes("Content-Disposition: form-data; name=\"uploaded_file\";filename=\""
						+ fileName + "\"" + lineEnd);
				dos.writeBytes(lineEnd);

				// create a buffer of maximum size
				bytesAvailable = fileInputStream.available();
				bufferSize = Math.min(bytesAvailable, maxBufferSize);
				buffer = new byte[bufferSize];

				// read file and write it into form...
				bytesRead = fileInputStream.read(buffer, 0, bufferSize);
				while (bytesRead > 0) {
					dos.write(buffer, 0, bufferSize);
					bytesAvailable = fileInputStream.available();
					bufferSize = Math.min(bytesAvailable, maxBufferSize);
					bytesRead = fileInputStream.read(buffer, 0, bufferSize);
				}

				// send multipart form data necesssary after file data...
				dos.writeBytes(lineEnd);
				dos.writeBytes(twoHyphens + boundary + twoHyphens + lineEnd);

				// Responses from the server (code and message)
				serverResponseCode = conn.getResponseCode();
				String serverResponseMessage = conn.getResponseMessage();
				Log.i("uploadFile", "HTTP Response is : "
						+ serverResponseMessage + ": " + serverResponseCode);
				fileInputStream.close();
				dos.flush();
				dos.close();

			} catch (MalformedURLException ex) {
				dialog.dismiss();
				ex.printStackTrace();
				runOnUiThread(new Runnable() {
					public void run() {
						messageText
								.setText("MalformedURLException Exception : check script url.");
						Toast.makeText(UploadToServer.this,
								"MalformedURLException", Toast.LENGTH_SHORT)
								.show();
					}
				});
				Log.e("Upload file to server", "error: " + ex.getMessage(), ex);
			} catch (Exception e) {
				dialog.dismiss();
				e.printStackTrace();
				runOnUiThread(new Runnable() {
					public void run() {
						messageText.setText("Got Exception : see logcat ");
						Toast.makeText(UploadToServer.this,
								"Got Exception : see logcat ",
								Toast.LENGTH_SHORT).show();
					}
				});
				Log.e("Upload file Exception :",
						"Exception : " + e.getMessage(), e);
//				reducing the string length to fit the requirement of the argument of "Log.e"

			}
			dialog.dismiss();
			return serverResponseCode;
		} // End else block
	}
}
