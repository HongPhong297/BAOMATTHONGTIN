/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package B2_W2;


import B1_W2.*;
import java.awt.HeadlessException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;


/**
 *
 * @author Administrator
 */
public class frm_TripleDES extends javax.swing.JFrame {

    /**
     * Creates new form frm_RailFence
     */
    public frm_TripleDES() {
        initComponents();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        btn_Encrypt = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        btn_Decrypt = new javax.swing.JButton();
        btn_Openfile = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        txt_plaintext = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        txt_ciphertext = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        txt_key = new javax.swing.JTextField();
        btn_Savefile = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel2.setText("Key");

        btn_Encrypt.setText("Encrypt");
        btn_Encrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_EncryptActionPerformed(evt);
            }
        });

        jLabel3.setText("CipherText");

        btn_Decrypt.setText("Decrypt");
        btn_Decrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_DecryptActionPerformed(evt);
            }
        });

        btn_Openfile.setText("Open Cipher Text");
        btn_Openfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_OpenfileActionPerformed(evt);
            }
        });

        txt_plaintext.setColumns(20);
        txt_plaintext.setRows(5);
        jScrollPane2.setViewportView(txt_plaintext);

        txt_ciphertext.setColumns(20);
        txt_ciphertext.setRows(5);
        jScrollPane3.setViewportView(txt_ciphertext);

        jLabel1.setText("PlainText");

        btn_Savefile.setText("Save File");
        btn_Savefile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_SavefileActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3)
                    .addComponent(jLabel2)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 36, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(btn_Encrypt)
                        .addGap(18, 18, 18)
                        .addComponent(btn_Decrypt)
                        .addGap(14, 14, 14)
                        .addComponent(btn_Savefile)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(btn_Openfile))
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jScrollPane2)
                        .addComponent(txt_key)
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 413, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addGap(20, 20, 20))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(12, 12, 12)
                        .addComponent(jLabel1)))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txt_key, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(14, 14, 14)
                        .addComponent(jLabel3)))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btn_Encrypt)
                    .addComponent(btn_Decrypt)
                    .addComponent(btn_Openfile)
                    .addComponent(btn_Savefile))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    private void btn_EncryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_EncryptActionPerformed
        // TODO add your handling code here:
        try {
            String plaintext = txt_plaintext.getText();
            String secretKey = txt_key.getText();
            if (secretKey.length() == 24) {
                String encryptedText = TripleDESCipher.encrypt(plaintext, secretKey);
                txt_ciphertext.setText(encryptedText);
            } else {
                JOptionPane.showMessageDialog(this, "Secret key must be 24 characters long", "Error", JOptionPane.ERROR_MESSAGE);
            }                             
        } catch(HeadlessException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            JOptionPane.showMessageDialog(this,"Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_btn_EncryptActionPerformed

    private void btn_DecryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_DecryptActionPerformed
        // TODO add your handling code here:
        try {
            String ciphertext = txt_ciphertext.getText();
            String secretKey = txt_key.getText();
            if (secretKey.length() == 24) {
                String decryptedText = TripleDESCipher.decrypt(ciphertext, secretKey);
                txt_plaintext.setText(decryptedText);
            } else {
                JOptionPane.showMessageDialog(this, "Secret key must be 24 characters long", "Error", JOptionPane.ERROR_MESSAGE);
            }                             
        } catch(HeadlessException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            JOptionPane.showMessageDialog(this,"Invalid key");
        }
    }//GEN-LAST:event_btn_DecryptActionPerformed

    private void btn_OpenfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_OpenfileActionPerformed
        // TODO add your handling code here:
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Open file containing ciphertext");
        int userSelection = fileChooser.showOpenDialog(this);
        if(userSelection == JFileChooser.APPROVE_OPTION) {
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(fileChooser.getSelectedFile()))) {
                JOptionPane.showMessageDialog(this, "File opened successfully");
                txt_ciphertext.read(bufferedReader, null);
                txt_key.setText("");
                txt_plaintext.setText("");

            } catch(IOException e) {
                JOptionPane.showMessageDialog(this, "Error opening file" + e.getMessage());
            }
        }
        
    }//GEN-LAST:event_btn_OpenfileActionPerformed

    private void btn_SavefileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_SavefileActionPerformed

        // TODO add your handling code here:
        String ciphertext = txt_ciphertext.getText(); // Sửa lỗi cú pháp khai báo và gán giá trị
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Ciphertext to File");
        int userSelection = fileChooser.showSaveDialog(this); // Sửa lỗi khai báo biến userSelection

        if (userSelection == JFileChooser.APPROVE_OPTION) { // Sửa cú pháp kiểm tra điều kiện
            File fileToSave = fileChooser.getSelectedFile(); // Sửa cú pháp khai báo biến fileToSave
            try (FileWriter writer = new FileWriter(fileToSave.getAbsolutePath() + ".txt")) {
                writer.write(ciphertext);
                JOptionPane.showMessageDialog(this, "Ciphertext saved to file successfully.",
                        "Success", JOptionPane.INFORMATION_MESSAGE); // Sửa lỗi thiếu dấu ngoặc và cách viết
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE); // Sửa lỗi thiếu dấu ngoặc
            }
        }


    }//GEN-LAST:event_btn_SavefileActionPerformed
    
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(frm_TripleDES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(frm_TripleDES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(frm_TripleDES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(frm_TripleDES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new frm_TripleDES().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btn_Decrypt;
    private javax.swing.JButton btn_Encrypt;
    private javax.swing.JButton btn_Openfile;
    private javax.swing.JButton btn_Savefile;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JTextArea txt_ciphertext;
    private javax.swing.JTextField txt_key;
    private javax.swing.JTextArea txt_plaintext;
    // End of variables declaration//GEN-END:variables

    
}
