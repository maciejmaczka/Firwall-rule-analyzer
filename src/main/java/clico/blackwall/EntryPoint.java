
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package clico.blackwall;

import General.Windows.Select_Vendor;
import CheckPoint.Windows.CheckPoint_MainWindow;
import PaloAlto.Windows.PaloAlto_MainWindow;
import Juniper.Windows.Juniper_MainWindow;
/**
 *
 * @author Maciej
 */
public class EntryPoint {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        
          CheckPoint_MainWindow gui_Main_Window = new CheckPoint_MainWindow();
          gui_Main_Window.setVisible(true);
        
   
    /*    Select_Vendor select_vendor_window = new Select_Vendor(null, true);
        select_vendor_window.setLocationRelativeTo ( null );
        select_vendor_window.setResizable(false);
        select_vendor_window.setVisible(true);
        
       
        String vendor = select_vendor_window.getVendor();
        
        System.out.println(vendor);
        
      
        
        if (vendor.equals("CheckPoint"))
        {
         
            CheckPoint_MainWindow gui_Main_Window = new CheckPoint_MainWindow();
            gui_Main_Window.setVisible(true);
        
        }
        
        if (vendor.equals("Juniper"))
        {
            
            Juniper_MainWindow gui_Main_Window = new Juniper_MainWindow();
            gui_Main_Window.setVisible(true);
            
            
        }
        
        if (vendor.equals("PaloAlto"))
        {
            
            PaloAlto_MainWindow gui_Main_Window = new PaloAlto_MainWindow();
            gui_Main_Window.setVisible(true);
            
            
        }
        
    */
    }
    
}
