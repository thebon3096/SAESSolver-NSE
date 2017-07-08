import java.awt.Color;
import java.awt.Desktop;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Font;
import com.itextpdf.text.Font.FontFamily;
import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfContentByte;
import com.itextpdf.text.pdf.AcroFields.Item;
import com.itextpdf.text.pdf.PdfCopy;
import com.itextpdf.text.pdf.PdfDocument;
import com.itextpdf.text.pdf.PdfImportedPage;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSmartCopy;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;

public class SolveSAES {
	
	private final String src = "SimplifiedAES.pdf";
	
	private final String[][] sbox = {
										{"9", "4", "A", "B"},
										{"D", "1", "8", "5"},
										{"6", "2", "0", "3"},
										{"C", "E", "F", "7"}
									};
	
	String gf4[] = {"0", "4", "8", "C", 
					"3", "7", "B", "F",
					"6", "2", "E", "A",
					"5", "1", "D", "9"}; 
	
	public SolveSAES(String[] plainText, String[] key) {
		
		String dest = System.getProperty("user.home")+"/Desktop/SolvedAES.pdf";
		String tempSolutionPath = System.getProperty("user.home")+"/Desktop/temp.pdf";
		String sboxPath = "SBOX.pdf";
		
		try {
			InputStream in = getClass().getClassLoader().getResourceAsStream(src);
			PdfReader r = new PdfReader(in);
			
			PdfStamper stamper = new PdfStamper(r, new FileOutputStream(tempSolutionPath));
			AcroFields af = stamper.getAcroFields();
			
			Map<String, Item> fields = af.getFields();
			for(String fieldTags : fields.keySet()){
				af.setFieldProperty(fieldTags, "textsize", new Float(14), null);
			}
			
			/*
			 * Set Plain Text
			 */
			
			Integer pt1 = Integer.parseInt(plainText[0], 16);
			Integer pt2 = Integer.parseInt(plainText[1], 16);
			Integer pt3 = Integer.parseInt(plainText[2], 16);
			Integer pt4 = Integer.parseInt(plainText[3], 16);
			
			af.setField("pt1", String.format("%4s", Integer.toBinaryString(pt1)).replace(' ', '0'));
			af.setField("pt2", String.format("%4s", Integer.toBinaryString(pt2)).replace(' ', '0'));
			af.setField("pt3", String.format("%4s", Integer.toBinaryString(pt3)).replace(' ', '0'));
			af.setField("pt4", String.format("%4s", Integer.toBinaryString(pt4)).replace(' ', '0'));
			
			/*
			 * Set Key
			 */
			
			Integer w00 = Integer.parseInt(key[0], 16);
			Integer w01 = Integer.parseInt(key[1], 16);
			Integer w10 = Integer.parseInt(key[2], 16);
			Integer w11 = Integer.parseInt(key[3], 16);
			
			String binaryStringW00 = get4BitNibble(w00);
			String binaryStringW01 = get4BitNibble(w01);
			String binaryStringW10 = get4BitNibble(w10);
			String binaryStringW11 = get4BitNibble(w11);
			
			af.setField("w00", binaryStringW00);
			af.setField("w01", binaryStringW01);
			af.setField("w10", binaryStringW10);
			af.setField("w11", binaryStringW11);
			
			/*
			 * SubstituteNibble(RotateNibble(w1))
			 */
			
			Integer sw11 = substituteNibble(binaryStringW11);
			Integer sw10 = substituteNibble(binaryStringW10);
			
			String binaryStringSW11 = get4BitNibble(sw11);
			String binaryStringSW10 = get4BitNibble(sw10);
			
			af.setField("sw11", binaryStringSW11);
			af.setField("sw10", binaryStringSW10);
			
			/*
			 * Calculate w20 & w21
			 */
			
			Integer w20 = w00 ^ 8 ^ sw11;
			Integer w21 = w01 ^ 0 ^ sw10;
			
			String binaryStringW20 = get4BitNibble(w20);
			String binaryStringW21 = get4BitNibble(w21);
			
			af.setField("w20", binaryStringW20);
			af.setField("w21", binaryStringW21);
			
			/*
			 * Calculate w30 & w31
			 */
			
			Integer w30 = w20 ^ w10;
			Integer w31 = w21 ^ w11;
			
			String binaryStringW30 = get4BitNibble(w30);
			String binaryStringW31 = get4BitNibble(w31);
			
			af.setField("w30", binaryStringW30);
			af.setField("w31", binaryStringW31);
			
			/*
			 * SubstituteNibble(RotateNibble(w3))
			 */
			
			Integer sw31 = substituteNibble(binaryStringW31);
			Integer sw30 = substituteNibble(binaryStringW30);
			
			String binaryStringSW31 = get4BitNibble(sw31);
			String binaryStringSW30 = get4BitNibble(sw30);
			
			af.setField("sw31", binaryStringSW31);
			af.setField("sw30", binaryStringSW30);
			
			/*
			 * Calculate w40 & w41
			 */
			
			Integer w40 = w20 ^ 3 ^ sw31;
			Integer w41 = w21 ^ 0 ^ sw30;
			
			String binaryStringW40 = get4BitNibble(w40);
			String binaryStringW41 = get4BitNibble(w41);
			
			af.setField("w40", binaryStringW40);
			af.setField("w41", binaryStringW41);
			
			/*
			 * Calculate w50 & w51
			 */
			
			Integer w50 = w40 ^ w30;
			Integer w51 = w41 ^ w31;
			
			String binaryStringW50 = get4BitNibble(w50);
			String binaryStringW51 = get4BitNibble(w51);
			
			af.setField("w50", binaryStringW50);
			af.setField("w51", binaryStringW51);
			
			/*
			 * Add Round Key 0
			 */
			
			Integer bit11 = pt1 ^ w00;
			Integer bit12 = pt2 ^ w01;
			Integer bit13 = pt3 ^ w10;
			Integer bit14 = pt4 ^ w11;
			
			String binaryStringBIT11 = get4BitNibble(bit11);
			String binaryStringBIT12 = get4BitNibble(bit12);
			String binaryStringBIT13 = get4BitNibble(bit13);
			String binaryStringBIT14 = get4BitNibble(bit14);
			
			af.setField("bit11", binaryStringBIT11);
			af.setField("bit12", binaryStringBIT12);
			af.setField("bit13", binaryStringBIT13);
			af.setField("bit14", binaryStringBIT14);
			
			af.setField("it11", Integer.toHexString(bit11).toUpperCase());
			af.setField("it12", Integer.toHexString(bit12).toUpperCase());
			af.setField("it13", Integer.toHexString(bit13).toUpperCase());
			af.setField("it14", Integer.toHexString(bit14).toUpperCase());
			
			/*
			 * Round 1
			 */
			
			/*
			 * Substitute Nibbles of IT1
			 */
			
			Integer sbit11 = substituteNibble(binaryStringBIT11);
			Integer sbit12 = substituteNibble(binaryStringBIT12);
			Integer sbit13 = substituteNibble(binaryStringBIT13);
			Integer sbit14 = substituteNibble(binaryStringBIT14);
			
			String binaryStringSBIT11 = get4BitNibble(sbit11);
			String binaryStringSBIT12 = get4BitNibble(sbit12);
			String binaryStringSBIT13 = get4BitNibble(sbit13);
			String binaryStringSBIT14 = get4BitNibble(sbit14);
			
			af.setField("sbit11", binaryStringSBIT11);
			af.setField("sbit12", binaryStringSBIT12);
			af.setField("sbit13", binaryStringSBIT13);
			af.setField("sbit14", binaryStringSBIT14);
			
			af.setField("it21", Integer.toHexString(sbit11).toUpperCase());
			af.setField("it22", Integer.toHexString(sbit12).toUpperCase());
			af.setField("it23", Integer.toHexString(sbit13).toUpperCase());
			af.setField("it24", Integer.toHexString(sbit14).toUpperCase());
			
			/*
			 * shift rows of IT2
			 */
			
			af.setField("it31", Integer.toHexString(sbit11).toUpperCase());
			af.setField("it32", Integer.toHexString(sbit14).toUpperCase());
			af.setField("it33", Integer.toHexString(sbit13).toUpperCase());
			af.setField("it34", Integer.toHexString(sbit12).toUpperCase());
			
			/*
			 * Mix Columns
			 */
			
			Integer s000 = sbit11;
			Integer s001 = gf4x(sbit14);
			Integer bit41 = s000 ^ s001;
			
			String binaryStringS000 = get4BitNibble(s000);
			String binaryStringS001 = get4BitNibble(s001);
			String binaryStringBIT41 = get4BitNibble(bit41);
			
			af.setField("s000", binaryStringS000);
			af.setField("s001", binaryStringS001);
			af.setField("bit41", binaryStringBIT41);
			
			Integer s010 = sbit13;
			Integer s011 = gf4x(sbit12);
			Integer bit43 = s010 ^ s011;
			
			String binaryStringS010 = get4BitNibble(s010);
			String binaryStringS011 = get4BitNibble(s011);
			String binaryStringBIT43 = get4BitNibble(bit43);
			
			af.setField("s010", binaryStringS010);
			af.setField("s011", binaryStringS011);
			af.setField("bit43", binaryStringBIT43);
			
			Integer s100 = gf4x(sbit11);
			Integer s101 = sbit14;
			Integer bit42 = s100 ^ s101;
			
			String binaryStringS100 = get4BitNibble(s100);
			String binaryStringS101 = get4BitNibble(s101);
			String binaryStringBIT42 = get4BitNibble(bit42);
			
			af.setField("s100", binaryStringS100);
			af.setField("s101", binaryStringS101);
			af.setField("bit42", binaryStringBIT42);
			
			Integer s110 = gf4x(sbit13);
			Integer s111 = sbit12;
			Integer bit44 = s110 ^ s111;
			
			String binaryStringS110 = get4BitNibble(s110);
			String binaryStringS111 = get4BitNibble(s111);
			String binaryStringBIT44 = get4BitNibble(bit44);
			
			af.setField("s110", binaryStringS110);
			af.setField("s111", binaryStringS111);
			af.setField("bit44", binaryStringBIT44);
			
			af.setField("it41", Integer.toHexString(bit41).toUpperCase());
			af.setField("it42", Integer.toHexString(bit42).toUpperCase());
			af.setField("it43", Integer.toHexString(bit43).toUpperCase());
			af.setField("it44", Integer.toHexString(bit44).toUpperCase());
			
			/*
			 * Add Round Key to IT4
			 */
			
			Integer bit51 = bit41 ^ w20;
			Integer bit52 = bit42 ^ w21;
			Integer bit53 = bit43 ^ w30;
			Integer bit54 = bit44 ^ w31;
			
			String binaryStringBIT51 = get4BitNibble(bit51);
			String binaryStringBIT52 = get4BitNibble(bit52);
			String binaryStringBIT53 = get4BitNibble(bit53);
			String binaryStringBIT54 = get4BitNibble(bit54);
			
			af.setField("bit51", binaryStringBIT51);
			af.setField("bit52", binaryStringBIT52);
			af.setField("bit53", binaryStringBIT53);
			af.setField("bit54", binaryStringBIT54);
			
			af.setField("it51", Integer.toHexString(bit51).toUpperCase());
			af.setField("it52", Integer.toHexString(bit52).toUpperCase());
			af.setField("it53", Integer.toHexString(bit53).toUpperCase());
			af.setField("it54", Integer.toHexString(bit54).toUpperCase());
			
			
			/*
			 * Round 2
			 */
			
			/*
			 * Substitute Nibbles of IT5
			 */
			
			Integer sbit51 = substituteNibble(binaryStringBIT51);
			Integer sbit52 = substituteNibble(binaryStringBIT52);
			Integer sbit53 = substituteNibble(binaryStringBIT53);
			Integer sbit54 = substituteNibble(binaryStringBIT54);
			
			String binaryStringSBIT51 = get4BitNibble(sbit51);
			String binaryStringSBIT52 = get4BitNibble(sbit52);
			String binaryStringSBIT53 = get4BitNibble(sbit53);
			String binaryStringSBIT54 = get4BitNibble(sbit54);
			
			af.setField("sbit51", binaryStringSBIT51);
			af.setField("sbit52", binaryStringSBIT52);
			af.setField("sbit53", binaryStringSBIT53);
			af.setField("sbit54", binaryStringSBIT54);
			
			af.setField("it61", Integer.toHexString(sbit51).toUpperCase());
			af.setField("it62", Integer.toHexString(sbit52).toUpperCase());
			af.setField("it63", Integer.toHexString(sbit53).toUpperCase());
			af.setField("it64", Integer.toHexString(sbit54).toUpperCase());
			
			/*
			 * Shift ROws of IT6
			 */
			
			af.setField("it71", Integer.toHexString(sbit51).toUpperCase());
			af.setField("it72", Integer.toHexString(sbit54).toUpperCase());
			af.setField("it73", Integer.toHexString(sbit53).toUpperCase());
			af.setField("it74", Integer.toHexString(sbit52).toUpperCase());
			
			/*
			 * Add Round Key 2
			 */
			
			Integer bit81 = sbit51 ^ w40;
			Integer bit82 = sbit54 ^ w41;
			Integer bit83 = sbit53 ^ w50;
			Integer bit84 = sbit52 ^ w51;
			
			String binaryStringBIT81 = get4BitNibble(bit81);
			String binaryStringBIT82 = get4BitNibble(bit82);
			String binaryStringBIT83 = get4BitNibble(bit83);
			String binaryStringBIT84 = get4BitNibble(bit84);
			
			af.setField("bit81", binaryStringBIT81);
			af.setField("bit82", binaryStringBIT82);
			af.setField("bit83", binaryStringBIT83);
			af.setField("bit84", binaryStringBIT84);
			
			af.setField("it81", Integer.toHexString(bit81).toUpperCase());
			af.setField("it82", Integer.toHexString(bit82).toUpperCase());
			af.setField("it83", Integer.toHexString(bit83).toUpperCase());
			af.setField("it84", Integer.toHexString(bit84).toUpperCase());
			
			InputStream sboxIn = getClass().getClassLoader().getResourceAsStream(sboxPath);
			PdfReader sbox = new PdfReader(sboxIn);
			
			stamper.setFormFlattening(true);
			
			stamper.close();
			r.close();
			
			/*
			 * MERGING SBOX PDF & SOLUTION
			 */
			
			Document d = new Document();
			PdfCopy copy = new PdfSmartCopy(d, new FileOutputStream(dest));
			d.open();
			try{
				FileInputStream f = new FileInputStream(tempSolutionPath);
				PdfReader p = new PdfReader(f);
				for(int i = 1; i<=p.getNumberOfPages(); ++i){
					copy.addPage(copy.getImportedPage(p, i));
				}
				f.close();
				p.close();
				
				InputStream inp = getClass().getClassLoader().getResourceAsStream(sboxPath);
				p = new PdfReader(inp);
				for(int i = 1; i<=p.getNumberOfPages(); ++i){
					copy.addPage(copy.getImportedPage(p, i));
				}
				inp.close();
			}catch(IOException e2){
				e2.printStackTrace();
			}
			d.close();
			copy.freeReader(sbox);
			sbox.close();
			
		} catch (IOException | DocumentException e) {
			e.printStackTrace();
		}finally{
			File tempFile = new File(tempSolutionPath);
			tempFile.delete();
			try {
				Desktop.getDesktop().open(new File(dest));
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	Integer gf4x(Integer b){
		return Integer.parseInt(gf4[b], 16);
	}
	
	String get4BitNibble(Integer a){
		return String.format("%4s", Integer.toBinaryString(a)).replace(' ', '0');
	}
	
	Integer substituteNibble(String nib){
		Integer row = Integer.parseInt(nib.substring(0, 2), 2);
		Integer column = Integer.parseInt(nib.substring(2, 4), 2);
		return Integer.parseInt(sbox[row][column], 16);
	}
	
	static void inputGUI(){
		
		String plainText[] = new String[4];
		String key[] = new String[4];
		
		JFrame f = new JFrame("Simplified AES");
		f.setLayout(null);
		f.setSize(420, 300);
		f.setLocationRelativeTo(null);
		f.setResizable(false);
		f.getContentPane().setBackground(new Color(124, 77, 238));
		
		JLabel l = new JLabel("Simplified AES", SwingConstants.CENTER);
		l.setFont((new java.awt.Font("Arial", Font.BOLD, 40)));
		l.setForeground(Color.WHITE);		
		l.setBorder(BorderFactory.createDashedBorder(null, 5, 5, 5, false));
		f.getContentPane().add(l).setBounds(0, 0, f.getWidth()-5, 100);;
		
		JLabel plainTextLabel = new JLabel("PlainText: ", SwingConstants.CENTER);
		plainTextLabel.setFont(new java.awt.Font("Arial", Font.NORMAL, 15));
		plainTextLabel.setForeground(Color.WHITE);
		JLabel keyLabel = new JLabel("Key: ", SwingConstants.CENTER);
		keyLabel.setFont(new java.awt.Font("Arial", Font.NORMAL, 15));
		keyLabel.setForeground(Color.WHITE);
		
		f.getContentPane().add(plainTextLabel).setBounds(50, 100, 100, 50);
		f.getContentPane().add(keyLabel).setBounds(50, 150, 100, 50);;
		
		JTextField pt[] = new JTextField[4];
		JTextField k[] = new JTextField[4];
		for(int i = 0; i<4; ++i){
			pt[i] = new JTextField();
			pt[i].setFont(new java.awt.Font("Arial", Font.NORMAL, 15));
			pt[i].setHorizontalAlignment(SwingConstants.CENTER);
			
			k[i] = new JTextField();
			k[i].setFont(new java.awt.Font("Arial", Font.NORMAL, 15));
			k[i].setHorizontalAlignment(SwingConstants.CENTER);
		}
		
		f.getContentPane().add(pt[0]).setBounds(150, 115, 30, 25);
		f.getContentPane().add(pt[1]).setBounds(200, 115, 30, 25);
		f.getContentPane().add(pt[2]).setBounds(250, 115, 30, 25);
		f.getContentPane().add(pt[3]).setBounds(300, 115, 30, 25);
		
		f.getContentPane().add(k[0]).setBounds(150, 165, 30, 25);
		f.getContentPane().add(k[1]).setBounds(200, 165, 30, 25);
		f.getContentPane().add(k[2]).setBounds(250, 165, 30, 25);
		f.getContentPane().add(k[3]).setBounds(300, 165, 30, 25);
		
		JButton solve = new JButton("Solve");
		f.getContentPane().add(solve).setBounds(150, 210, 90, 30);
		
		solve.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				try{
					for(int i = 0; i<4; ++i){
						String pts = pt[i].getText();
						if(pts.length() <= 0 || pts.length() > 1)
							throw new Exception();
						plainText[i] = pts;
						
						String ks = k[i].getText();
						if(ks.length() <= 0 || ks.length() > 1)
							throw new Exception();
						key[i] = ks;
					}
					new SolveSAES(plainText, key);
					
				}catch(Exception e1){
					JOptionPane.showMessageDialog(f, "Invalid Inputs!", "Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		
		f.setVisible(true);
		f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
	
	public static void main(String[] args) {
		inputGUI();
	}

}
