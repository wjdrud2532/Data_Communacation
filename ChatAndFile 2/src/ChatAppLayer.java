

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.IntStream;

public class ChatAppLayer implements BaseLayer {
    public int nUpperLayerCount = 0;
    public String pLayerName = null;
    public BaseLayer p_UnderLayer = null;
    public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
    _CHAT_APP m_sHeader;

    private byte[] fragBytes;
    private int fragCount = 0;
    private ArrayList<Boolean> ackChk = new ArrayList<Boolean>();

    private class _CHAT_APP {
        byte[] capp_totlen;
        byte capp_type;
        byte capp_unused;
        byte[] capp_data;

        public _CHAT_APP() {
            this.capp_totlen = new byte[2];
            this.capp_type = 0x00;
            this.capp_unused = 0x00;
            this.capp_data = null;
        }
    }

    public ChatAppLayer(String pName) {
        // super(pName);
        // TODO Auto-generated constructor stub
        pLayerName = pName;
        ResetHeader();
        ackChk.add(true);
    }

    private void ResetHeader() {
        m_sHeader = new _CHAT_APP();
    }

    private byte[] objToByte(_CHAT_APP Header, byte[] input, int length) {
        byte[] buf = new byte[length + 4];

        buf[0] = Header.capp_totlen[0];
        buf[1] = Header.capp_totlen[1];
        buf[2] = Header.capp_type;
        buf[3] = Header.capp_unused;

        if (length >= 0) System.arraycopy(input, 0, buf, 4, length);

        return buf;
    }

    public byte[] RemoveCappHeader(byte[] input, int length) {
        byte[] cpyInput = new byte[length - 4];
        System.arraycopy(input, 4, cpyInput, 0, length - 4);
        input = cpyInput;
        return input;
    }

    private void waitACK() { //ACK 체크
        while (ackChk.size() <= 0) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        ackChk.remove(0);
    }

    private byte[] encrypt(byte[] input) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(((ChatAndFileDlg)GetUpperLayer(0)).encryptionKeyString.toCharArray(), "SALTSALT".getBytes(StandardCharsets.UTF_8), 65536, 256);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[] {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6});
            String algorithm = "AES/CBC/PKCS5Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secret, ivParameterSpec);
            return cipher.doFinal(input);
        } catch (Exception e) {
            //error
            System.out.println("cannot encrypt");
            return new byte[0];
        }
    }

    private byte[] decrypt(byte[] input) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(((ChatAndFileDlg)GetUpperLayer(0)).encryptionKeyString.toCharArray(), "SALTSALT".getBytes(StandardCharsets.UTF_8), 65536, 256);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec)
                    .getEncoded(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[] {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6});
            String algorithm = "AES/CBC/PKCS5Padding";
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secret, ivParameterSpec);
            byte[] cipherText = cipher.doFinal(input);
            return cipherText;
        } catch (Exception e) {
            //error
            System.out.println("cannot decrypt");
            return new byte[0];
        }
    }

    private void fragSend(byte[] input, int length) {
        byte[] bytes = new byte[10];

        int i = 10;
        m_sHeader.capp_totlen = intToByte2(length);
        m_sHeader.capp_type = (byte) (0x01);

        // 첫번째 전송
        System.arraycopy(input, 0, bytes, 0, 10);
        bytes = objToByte(m_sHeader, bytes, 10);
        this.GetUnderLayer().Send(bytes, bytes.length);
        System.out.println("[ChatApp FragSend 1] : " + Arrays.toString(bytes));

        // 2번째 전송부터 n-1번째 전송까지는 타입을 0x02로 하여 전송한다.
        m_sHeader.capp_totlen = intToByte2(10);
        m_sHeader.capp_type = (byte) 0x02;
        while (i + 10 < length) {
            waitACK();
            System.arraycopy(input, i, bytes, 0, 10);
            bytes = objToByte(m_sHeader, bytes, 10);
            this.GetUnderLayer().Send(bytes, bytes.length);
            System.out.println("[ChatApp FragSend 2..n-1] : " + Arrays.toString(bytes));
            i += 10;
        }

        // 마지막 전송은 타입을 0x03으로 하여 전송한다.
        waitACK();
        m_sHeader.capp_totlen = intToByte2(length - i);
        m_sHeader.capp_type = (byte) (0x03);
        System.arraycopy(input, i, bytes, 0, length - i);
        bytes = objToByte(m_sHeader, bytes, length - i);
        this.GetUnderLayer().Send(bytes, length - i + 4);
        System.out.println("[ChatApp FragSend n] : " + Arrays.toString(bytes) + ", length: " + (length - i));

        // HW4 end
    }
 
    public boolean Send(byte[] input, int length) {
        byte[] bytes;
        System.out.println("Plain1 " + Arrays.toString(input));
        System.out.println("Encrypted1: " + Arrays.toString(encrypt(input)));
        input = encrypt(input);
        length = input.length;
        m_sHeader.capp_totlen = intToByte2(length);
        m_sHeader.capp_type = (byte) (0x00);

        // HW4 begin
        if (length > 10) {
            fragSend(input, length);
        } else {
            // 기존 코드처럼 그냥 하위 레이어로 전송하면 된다.
            bytes = objToByte(m_sHeader, input, length);
            this.GetUnderLayer().Send(bytes, length + 4);
        }
        // HW4 end
        return true;
    }
 
    public synchronized boolean Receive(byte[] input) {
        byte[] data, tempBytes;
        int tempType = 0;

        if (input == null) {
        	ackChk.add(true);
        	return true;
        }
        
        tempType |= (byte) (input[2] & 0xFF);
        
        if (tempType == 0) {
            // HW4 begin
            // 단편화 없이 수신한 데이터는 바로 상위 레이어로 전송한다.
            data = RemoveCappHeader(input, input.length);
            this.GetUpperLayer(0).Receive(decrypt(data));
            // HW4 end
        }
        else{
            // HW4 begin
            // 단편화가 되어 수신한 데이터는 상위 레이어로 전송하지 않고 모은다.
            data = RemoveCappHeader(input, input.length);
            System.out.println("[ChatApp Receive] : " + Arrays.toString(data));
            if (tempType == 1) {
                // type이 0x01이면 총 길이가 들어오기 때문에 fragBytes에 길이만큼 할당시킨다.
                int len = byte2ToInt(input[0], input[1]);
                fragBytes = new byte[len];
                System.arraycopy(data, 0, fragBytes, 0, 10);
                fragCount += 10;
            } else if (tempType == 2) {
                // 2..n-1 사이의 단편화 중간 부분.
                System.arraycopy(data, 0, fragBytes, fragCount, 10);
                fragCount += 10;
            } else if (tempType == 3) {
                // 마지막 데이터를 받았으므로 전체 데이터를 상위 레이어로 전송한다.
                int len = byte2ToInt(input[0], input[1]);
                System.out.println("len: " + len);
                System.arraycopy(data, 0, fragBytes, fragCount, len);

                System.out.println("Before Decrypted: " + Arrays.toString(fragBytes));
                System.out.println("Plain: " + Arrays.toString(decrypt(fragBytes)));
                fragBytes = decrypt(fragBytes);

                this.GetUpperLayer(0).Receive(fragBytes);
                fragCount = 0;
            }

            // HW4 end
        }
        this.GetUnderLayer().Send(null, 0); // ack 송신
        return true;
    }
    
    private byte[] intToByte2(int value) {
        byte[] temp = new byte[2];
        temp[0] |= (byte) ((value & 0xFF00) >> 8);
        temp[1] |= (byte) (value & 0xFF);

        return temp;
    }

    private int byte2ToInt(byte value1, byte value2) {
        return (int)((value1 << 8) | (value2));
    }

    @Override
    public String GetLayerName() {
        // TODO Auto-generated method stub
        return pLayerName;
    }

    @Override
    public BaseLayer GetUnderLayer() {
        // TODO Auto-generated method stub
        if (p_UnderLayer == null)
            return null;
        return p_UnderLayer;
    }

    @Override
    public BaseLayer GetUpperLayer(int nindex) {
        // TODO Auto-generated method stub
        if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
            return null;
        return p_aUpperLayer.get(nindex);
    }

    @Override
    public void SetUnderLayer(BaseLayer pUnderLayer) {
        // TODO Auto-generated method stub
        if (pUnderLayer == null)
            return;
        this.p_UnderLayer = pUnderLayer;
    }

    @Override
    public void SetUpperLayer(BaseLayer pUpperLayer) {
        // TODO Auto-generated method stub
        if (pUpperLayer == null)
            return;
        this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
    }

    @Override
    public void SetUpperUnderLayer(BaseLayer pUULayer) {
        this.SetUpperLayer(pUULayer);
        pUULayer.SetUnderLayer(this);
    }
}
