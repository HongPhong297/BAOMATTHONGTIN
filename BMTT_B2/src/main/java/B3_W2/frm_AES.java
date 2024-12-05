/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package B3_W2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;

/**
 *
 * @author roxph
 */
public class frm_AES extends javax.swing.JFrame {
    private static final String REGISTRATION_FILE = "registration.key";
    private boolean isLoggedIn = false;
    /**
     * Creates new form frm_AES
     */
    public frm_AES() {
        initComponents();
        updateButtonState();
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        txt_ticket = new javax.swing.JTextField();
        txt_username = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        txt_plaintext = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        txt_ciphertext = new javax.swing.JTextArea();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        btn_login = new javax.swing.JButton();
        btn_register = new javax.swing.JButton();
        btn_encrypt = new javax.swing.JButton();
        btn_decrypt = new javax.swing.JButton();
        txt_password = new javax.swing.JPasswordField();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        txt_plaintext.setColumns(20);
        txt_plaintext.setRows(5);
        jScrollPane1.setViewportView(txt_plaintext);

        txt_ciphertext.setColumns(20);
        txt_ciphertext.setRows(5);
        jScrollPane2.setViewportView(txt_ciphertext);

        jLabel1.setFont(new java.awt.Font("Segoe UI", 0, 24)); // NOI18N
        jLabel1.setText("AES CIPHER DEMO");

        jLabel2.setText("USERNAME");

        jLabel3.setText("PASSWORD");

        jLabel4.setText("PLAINTEXT");

        jLabel5.setText("CIPHERTEXT");

        jLabel6.setText("TICKET");
        jLabel6.setToolTipText("");

        btn_login.setText("LOGIN");
        btn_login.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_loginActionPerformed(evt);
            }
        });

        btn_register.setText("REGISTER");
        btn_register.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_registerActionPerformed(evt);
            }
        });

        btn_encrypt.setText("ENCRYPT");
        btn_encrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_encryptActionPerformed(evt);
            }
        });

        btn_decrypt.setText("DECRYPT");
        btn_decrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btn_decryptActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(19, 19, 19)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel2)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(txt_username, javax.swing.GroupLayout.PREFERRED_SIZE, 409, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 63, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 409, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jLabel5)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 33, Short.MAX_VALUE)
                                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 409, javax.swing.GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(jLabel6)
                                    .addComponent(jLabel3))
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(txt_ticket, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE)
                                    .addComponent(txt_password))))
                        .addGap(85, 85, 85))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(193, 193, 193))))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(btn_register)
                        .addGap(142, 142, 142)
                        .addComponent(btn_login)
                        .addGap(169, 169, 169))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(btn_encrypt)
                        .addGap(157, 157, 157)
                        .addComponent(btn_decrypt)
                        .addGap(149, 149, 149))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 31, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(35, 35, 35)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(txt_username, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2))
                .addGap(24, 24, 24)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(txt_password, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(txt_ticket, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btn_login)
                            .addComponent(btn_register))
                        .addGap(9, 9, 9)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel4))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 47, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 115, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabel5))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(btn_encrypt)
                            .addComponent(btn_decrypt))
                        .addGap(8, 8, 8))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel6)
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    
    private void updateButtonState() {
        btn_encrypt.setEnabled(isLoggedIn);
        btn_decrypt.setEnabled(isLoggedIn);
        
    }
    
    private void btn_registerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_registerActionPerformed
        // TODO add your handling code here:
        String username = txt_username.getText();
        String password = new String(txt_password.getPassword());
        
        if (!username.isEmpty() && !password.isEmpty()) {
            try {
                String registrationKey = AESCipher.generateRegistrationKey(username, password);
                AESCipher.saveRegistrationKeyToFile(registrationKey, REGISTRATION_FILE);
                JOptionPane.showMessageDialog(this, 
                        "Registration Successful. Registration Key Saved",
                        "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(this,
                        "Error Saving Registration Key: " + e.getMessage(),
                        "Erorr", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Username and Password cannot be empty",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
        
        
        
    }//GEN-LAST:event_btn_registerActionPerformed

    private void btn_loginActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_loginActionPerformed
        /**
         * Xử lý sự kiện nút đăng nhập.
         *
         * @param evt Sự kiện hành động
         */

        // Lấy thông tin người dùng
        String username = txt_username.getText();
        String password = new String(txt_password.getPassword());

        // Kiểm tra thông tin người dùng
        if (!username.isEmpty() && !password.isEmpty()) {
            try {
                // Đọc khóa đăng ký từ tệp
                String registrationKeyFromFile = AESCipher.readRegistrationKeyFromFile(REGISTRATION_FILE);

                // Tạo khóa đăng ký từ thông tin người dùng
                String registrationKey = AESCipher.generateRegistrationKey(username, password);

                // Kiểm tra khóa đăng ký
                if (registrationKeyFromFile.equals(registrationKey)) {
                    // Đăng nhập thành công
                    JOptionPane.showMessageDialog(
                            this,
                            "Đăng nhập thành công với khóa đăng ký: " + registrationKey,
                            "Thành công",
                            JOptionPane.INFORMATION_MESSAGE
                    );
                    txt_ticket.setText(registrationKey);
                    isLoggedIn = true;
                    updateButtonState();
                } else {
                    // Thông tin người dùng không chính xác
                    JOptionPane.showMessageDialog(
                            this,
                            "Tên người dùng hoặc mật khẩu không chính xác.",
                            "Lỗi",
                            JOptionPane.ERROR_MESSAGE
                    );
                }
            } catch (IOException | ClassNotFoundException e) {
                // Lỗi đọc khóa đăng ký
                JOptionPane.showMessageDialog(
                        this,
                        "Lỗi đọc khóa đăng ký: " + e.getMessage(),
                        "Lỗi",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        } else {
            // Thông tin người dùng trống
            JOptionPane.showMessageDialog(
                    this,
                    "Tên người dùng và mật khẩu không được trống.",
                    "Lỗi",
                    JOptionPane.ERROR_MESSAGE
            );
        }
        // TODO add your handling code here:
    }//GEN-LAST:event_btn_loginActionPerformed

    private void btn_encryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_encryptActionPerformed

        // TODO add your handling code here:
        /**
         * Xử lý sự kiện nút mã hóa.
         *
         * @param evt Sự kiện hành động
         */
        // Lấy văn bản và khóa bí mật
        String plaintext = txt_plaintext.getText();
        String secretKey = new String(txt_password.getPassword());

        // Kiểm tra đầu vào
        if (!plaintext.isEmpty() && !secretKey.isEmpty()) {
            try {
                // Mã hóa văn bản
                String encryptedText = AESCipher.encrypt(plaintext, secretKey);
                txt_ciphertext.setText(encryptedText);
            } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
                // Hiển thị lỗi mã hóa
                JOptionPane.showMessageDialog(
                        this,
                        "Lỗi mã hóa: " + e.getMessage(),
                        "Lỗi",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        } else {
            // Hiển thị lỗi đầu vào trống
            JOptionPane.showMessageDialog(
                    this,
                    "Văn bản và khóa bí mật không được trống.",
                    "Lỗi",
                    JOptionPane.ERROR_MESSAGE
            );
        }

    }//GEN-LAST:event_btn_encryptActionPerformed

    private void btn_decryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btn_decryptActionPerformed
        // TODO add your handling code here:
        /**
         * Xử lý sự kiện nút giải mã.
         *
         * @param evt Sự kiện hành động
         */

        // Lấy văn bản đã mã hóa và khóa bí mật
        String ciphertext = txt_ciphertext.getText();
        String secretKey = new String(txt_password.getPassword());

        // Kiểm tra đầu vào
        if (!ciphertext.isEmpty() && !secretKey.isEmpty()) {
            try {
                // Giải mã văn bản
                String decryptedText = AESCipher.decrypt(ciphertext, secretKey);
                txt_plaintext.setText(decryptedText);
            } catch (Exception e) {
                // Hiển thị lỗi giải mã
                JOptionPane.showMessageDialog(
                        this,
                        "Lỗi giải mã: " + e.getMessage(),
                        "Lỗi",
                        JOptionPane.ERROR_MESSAGE
                );
            }
        } else {
            // Hiển thị lỗi đầu vào trống
            JOptionPane.showMessageDialog(
                    this,
                    "Văn bản đã mã hóa và khóa bí mật không được trống.",
                    "Lỗi",
                    JOptionPane.ERROR_MESSAGE
            );
        }

    }//GEN-LAST:event_btn_decryptActionPerformed
    
    
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
            java.util.logging.Logger.getLogger(frm_AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(frm_AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(frm_AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(frm_AES.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new frm_AES().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btn_decrypt;
    private javax.swing.JButton btn_encrypt;
    private javax.swing.JButton btn_login;
    private javax.swing.JButton btn_register;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea txt_ciphertext;
    private javax.swing.JPasswordField txt_password;
    private javax.swing.JTextArea txt_plaintext;
    private javax.swing.JTextField txt_ticket;
    private javax.swing.JTextField txt_username;
    // End of variables declaration//GEN-END:variables
}
