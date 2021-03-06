/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package General.Windows;

import javax.swing.JButton;

/**
 *
 * @author Maciej
 */
public class Select_Vendor extends javax.swing.JDialog {

    String main_path = "";
    String vendor = "";
    
    /**
     * Creates new form Select_Vendor
     */
    public Select_Vendor(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
        
        load_graphics();
    }

    
    public void load_graphics()
    {
          main_path = System.getProperty("user.dir");
        
        
        
     
      
          button_checkpoint.setIcon(new javax.swing.ImageIcon(main_path + "\\src\\main\\java\\Graphics\\CheckPoint.png"));
          button_juniper.setIcon(new javax.swing.ImageIcon(main_path + "\\src\\main\\java\\Graphics\\Juniper.png"));
          button_paloalto.setIcon(new javax.swing.ImageIcon(main_path + "\\src\\main\\java\\Graphics\\PaloAlto.png"));
          
    }
    
    
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        button_checkpoint = new javax.swing.JButton();
        button_juniper = new javax.swing.JButton();
        button_paloalto = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Select Firewall");
        setAlwaysOnTop(true);
        setResizable(false);

        button_checkpoint.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        button_checkpoint.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button_checkpointActionPerformed(evt);
            }
        });

        button_juniper.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button_juniperActionPerformed(evt);
            }
        });

        button_paloalto.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                button_paloaltoActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(button_checkpoint, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(button_juniper, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(button_paloalto, javax.swing.GroupLayout.PREFERRED_SIZE, 220, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(button_checkpoint, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button_juniper, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(button_paloalto, javax.swing.GroupLayout.PREFERRED_SIZE, 200, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void button_checkpointActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button_checkpointActionPerformed
       
        vendor = "CheckPoint";  
        this.setVisible(false);
        
        
        
    }//GEN-LAST:event_button_checkpointActionPerformed

    private void button_juniperActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button_juniperActionPerformed
      
        vendor = "Juniper";
        this.setVisible(false);
    }//GEN-LAST:event_button_juniperActionPerformed

    private void button_paloaltoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_button_paloaltoActionPerformed
      
        vendor = "PaloAlto";
        this.setVisible(false);
    }//GEN-LAST:event_button_paloaltoActionPerformed

    public String getVendor()
    {
        
        return vendor;
        
    }
    
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
            java.util.logging.Logger.getLogger(Select_Vendor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Select_Vendor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Select_Vendor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Select_Vendor.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                Select_Vendor dialog = new Select_Vendor(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton button_checkpoint;
    private javax.swing.JButton button_juniper;
    private javax.swing.JButton button_paloalto;
    // End of variables declaration//GEN-END:variables
}
