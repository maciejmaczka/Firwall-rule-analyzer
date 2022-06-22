/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint.Windows;

import CheckPoint.CheckPoint_Firewall_Local_Facts_Processor;
import General.Log;

import CheckPoint.CheckPoint_Management_API;
import CheckPoint.CheckPoint_Management_API_Object_Processor;
import CheckPoint.CheckPoint_Management_API_Rule_Processor;
import General.Config_File_Procesor;
import General.Log;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.text.DefaultCaret;
/**
 *
 * @author Maciej
 */
public class CheckPoint_MainWindow extends javax.swing.JFrame {

    
    Log log_handler;
    CheckPoint_Management_API CheckPoint_Management_API_handler;  
    
    // wszystkie objekty w jednym miejscu
    // jako prosty punkt do przekazywania dalej
    
    
    
    
    
    
    CheckPoint_Management_API_Rule_Processor Policy_Processor_Handler;
    CheckPoint_Management_API_Object_Processor Object_Processor_Handler;
    
    CheckPoint_Network_Object_Dictionary_Window network_object_explorer;
    
    
    CheckPoint_Firewall_Local_Facts_Processor firewall_local_facts;
    
    General.Config_File_Procesor config_file_processor;
    
    
    ////////////////////// temp ///////////////////////////
    
    boolean get_layers_in_progres = false;
    Map<String, Integer > table_columns ;
    

    /**
     * Creates new form MainWindow
     */
    public CheckPoint_MainWindow() {
        initComponents();
        setExtendedState(java.awt.Frame.MAXIMIZED_BOTH);


        main_window_class_initializer();



    }

    
    public void main_window_class_initializer()
    {
        
        log_handler = new Log(GUI_Log_Area);
        
        
        CheckPoint_Management_API_handler = new CheckPoint_Management_API();
        CheckPoint_Management_API_handler.log_handler = log_handler;
        //CheckPoint_Management_API_handler.merge_log_handler(log_handler);
        CheckPoint_Management_API_handler.merge_rule_table(GUI_Ruleset_Table, table_columns);

        DefaultCaret caret = (DefaultCaret) GUI_Log_Area.getCaret(); // ←
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);       // ←
    
        GUI_Scroll_Pane_Log_Area.setViewportView(GUI_Log_Area);
      //  JScrollPane scrollPane = new JScrollPane();
      //  scrollPane.setViewportView(GUI_Log_Area);

        
        load_ruleset_view();
        
        
        Policy_Processor_Handler = new CheckPoint_Management_API_Rule_Processor();
        Policy_Processor_Handler.log_handler = log_handler;
        CheckPoint_Management_API_handler.Policy_Processor_Handler = this.Policy_Processor_Handler;
      
        Object_Processor_Handler = new CheckPoint_Management_API_Object_Processor();
        CheckPoint_Management_API_handler.Object_Processor_Handler = Object_Processor_Handler;
        Object_Processor_Handler.log_handler = log_handler;
        
        network_object_explorer = new CheckPoint_Network_Object_Dictionary_Window();
        network_object_explorer.log_handler = log_handler;
        Object_Processor_Handler.network_object_explorer = network_object_explorer;
        Object_Processor_Handler.prepare_global_set();
        Object_Processor_Handler.network_object_explorer.log_handler = log_handler;
        
        firewall_local_facts = new CheckPoint_Firewall_Local_Facts_Processor();
        firewall_local_facts.log_handler = log_handler;
        firewall_local_facts.Object_Processor_Handler = Object_Processor_Handler;
        firewall_local_facts.network_object_explorer = network_object_explorer;
        firewall_local_facts.dynamic_object_ranges_local_facts = new HashSet<CheckPoint_Management_API_Object_Processor.ranges>();
        firewall_local_facts.Object_Processor_Handler.identity_awareness_local_facts = new HashMap<String, Integer>();  
        
        firewall_local_facts.Object_Processor_Handler.application_match_overide = new HashMap<>();
        
        config_file_processor = new Config_File_Procesor();        
        config_file_processor.log_handler = log_handler;
     
    }
    
    public int get_column_index_by_name(String column)
    {
        
        return table_columns.get(column);
        
    }
    
    public void hide_column(String column)
    {
        
            int columnIndex = get_column_index_by_name(column);
            TableColumnModel column_model = GUI_Ruleset_Table.getColumnModel() ;
            

            column_model.getColumn(columnIndex).setMinWidth(0);
            column_model.getColumn(columnIndex).setMaxWidth(0);
         
            // 2147483647 max
            // 15 min
            
    }
    
    public void show_column(String column)
    {
        
            int columnIndex = get_column_index_by_name(column);
            TableColumnModel column_model = GUI_Ruleset_Table.getColumnModel() ;
            

            column_model.getColumn(columnIndex).setMinWidth(15);
            column_model.getColumn(columnIndex).setMaxWidth(2147483647);
         
            // 2147483647 max
            // 15 min
            
    }
        
        public void show_column(Integer columnIndex)
    {
        
      //      int columnIndex = get_columnt_index_by_name(column);
            TableColumnModel column_model = GUI_Ruleset_Table.getColumnModel() ;
            

            column_model.getColumn(columnIndex).setMinWidth(15);
            column_model.getColumn(columnIndex).setMaxWidth(2147483647);
         
            // 2147483647 max
            // 15 min
            
    }
            
        
    
    public void load_ruleset_view()
    {
      
            table_columns = new HashMap<String,Integer>();
            
            
          
            DefaultTableModel table_model = new DefaultTableModel();
     
     
        
            GUI_Ruleset_Table.setModel(table_model);
            int col = 0;
 
            table_model.addColumn("No");   // 0
            table_columns.put("No", col);
            col++;
            table_model.addColumn("Enabled");  // 1 
            table_columns.put("Enabled", col);
            col++;
            table_model.addColumn("Hits");     // 2
            table_columns.put("Hits", col);
            col++;
            table_model.addColumn("Name" );    // 3
            table_columns.put("Name", col);
            col++;
            table_model.addColumn("Source");   // 4
            table_columns.put("Source", col);
            col++;
            table_model.addColumn("Src Machine"); // 5
            table_columns.put("Src Machine", col);
            col++;
            table_model.addColumn("Src Zone");  //  6
            table_columns.put("Src Zone", col);
            col++;
            table_model.addColumn("Destination"); // 7
            table_columns.put("Destination", col);
            col++;
            table_model.addColumn("Dst Machine");  // 8
            table_columns.put("Dst Machine", col);
            col++;
            table_model.addColumn("Dst Zone");  // 9
            table_columns.put("Dst Zone", col);
            col++;
            
            
            table_model.addColumn("Service");   // 10
            table_columns.put("Service", col);
            col++;
            table_model.addColumn("Srv Machine");     // 11 
            table_columns.put("Srv Machine", col);
            col++;
            table_model.addColumn("Content");  // 12
            table_columns.put("Content", col);
            col++;
            table_model.addColumn("Time");  // 13
            table_columns.put("Time", col);
            col++;
            table_model.addColumn("VPN");  // 14
            table_columns.put("VPN", col);
            col++; 
            table_model.addColumn("Action");  // 15
            table_columns.put("Action", col);
            col++;
            table_model.addColumn("Track");  // 16
            table_columns.put("Track", col);
            col++;
            
            table_model.addColumn("TP Profile");  // 17
            table_columns.put("TP Profile", col);
            col++;
            
            table_model.addColumn("Comment");  // 18
            table_columns.put("Comment", col);
             col++;
            
                      
            table_model.addColumn("Install");  // 19
            table_columns.put("Install", col);
            col++;
            
            table_model.addColumn("Metainfo");  // 19
            table_columns.put("Metainfo", col);
            col++; 
            
            
             // always hidden column
            table_model.addColumn("Highlight");  // 20
            table_columns.put("Highlight", col);
            col++;
            
         //   log_handler.log_in_gui(table_columns.get("No").toString());
               
            hide_column("Src Machine");
            hide_column("Src Zone");
            hide_column("Dst Machine");
            hide_column("Dst Zone");
            hide_column("Srv Machine");
            hide_column("TP Profile");
            hide_column("Enabled");
            
            
            hide_column("Highlight");
            
    }
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        GUI_Ruleset_Table = new javax.swing.JTable();
        GUI_Scroll_Pane_Log_Area = new javax.swing.JScrollPane();
        GUI_Log_Area = new javax.swing.JTextPane();
        GUI_Menu = new javax.swing.JMenuBar();
        jMenu3 = new javax.swing.JMenu();
        Item_CheckPoint_MGMT_API_Exit = new javax.swing.JMenuItem();
        jMenu1 = new javax.swing.JMenu();
        Item_CheckPoint_MGMT_API_Connection = new javax.swing.JMenuItem();
        jMenu2 = new javax.swing.JMenu();
        Item_CheckPoint_Get_Firewall_Facts = new javax.swing.JMenuItem();
        Item_CheckPoint_Get_Access_Control_Layer = new javax.swing.JMenuItem();
        jMenuItem2 = new javax.swing.JMenuItem();
        jMenu4 = new javax.swing.JMenu();
        Item_CheckPoint_Human_View = new javax.swing.JMenuItem();
        Item_CheckPoint_Machine_View = new javax.swing.JMenuItem();
        Item_CheckPoint_TP_View = new javax.swing.JMenuItem();
        jMenu5 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        jMenu6 = new javax.swing.JMenu();
        Item_Relaod_APP_Database = new javax.swing.JMenuItem();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("BlackWall");

        GUI_Ruleset_Table.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {

            }
        ));
        GUI_Ruleset_Table.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_ALL_COLUMNS);
        GUI_Ruleset_Table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        GUI_Ruleset_Table.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        jScrollPane1.setViewportView(GUI_Ruleset_Table);

        GUI_Log_Area.setCursor(new java.awt.Cursor(java.awt.Cursor.TEXT_CURSOR));
        GUI_Log_Area.setPreferredSize(new java.awt.Dimension(100, 700));
        GUI_Scroll_Pane_Log_Area.setViewportView(GUI_Log_Area);

        jMenu3.setText("File");

        Item_CheckPoint_MGMT_API_Exit.setText("Exit");
        Item_CheckPoint_MGMT_API_Exit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_MGMT_API_ExitActionPerformed(evt);
            }
        });
        jMenu3.add(Item_CheckPoint_MGMT_API_Exit);

        GUI_Menu.add(jMenu3);

        jMenu1.setText("Connect");

        Item_CheckPoint_MGMT_API_Connection.setText("Management API");
        Item_CheckPoint_MGMT_API_Connection.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_MGMT_API_ConnectionActionPerformed(evt);
            }
        });
        jMenu1.add(Item_CheckPoint_MGMT_API_Connection);

        GUI_Menu.add(jMenu1);

        jMenu2.setText("Get");

        Item_CheckPoint_Get_Firewall_Facts.setText("Firewall Facts (Offline)");
        Item_CheckPoint_Get_Firewall_Facts.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_Get_Firewall_FactsActionPerformed(evt);
            }
        });
        jMenu2.add(Item_CheckPoint_Get_Firewall_Facts);

        Item_CheckPoint_Get_Access_Control_Layer.setText("Access Control Layer (Online)");
        Item_CheckPoint_Get_Access_Control_Layer.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_Get_Access_Control_LayerActionPerformed(evt);
            }
        });
        jMenu2.add(Item_CheckPoint_Get_Access_Control_Layer);

        jMenuItem2.setText("Access Control Layer (From File)");
        jMenuItem2.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem2ActionPerformed(evt);
            }
        });
        jMenu2.add(jMenuItem2);

        GUI_Menu.add(jMenu2);

        jMenu4.setText("View");

        Item_CheckPoint_Human_View.setText("Human View");
        Item_CheckPoint_Human_View.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_Human_ViewActionPerformed(evt);
            }
        });
        jMenu4.add(Item_CheckPoint_Human_View);

        Item_CheckPoint_Machine_View.setText("Machine View");
        Item_CheckPoint_Machine_View.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_CheckPoint_Machine_ViewActionPerformed(evt);
            }
        });
        jMenu4.add(Item_CheckPoint_Machine_View);

        Item_CheckPoint_TP_View.setText("Threat Prevention View");
        jMenu4.add(Item_CheckPoint_TP_View);

        GUI_Menu.add(jMenu4);

        jMenu5.setText("Objects");

        jMenuItem1.setText("Network");
        jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jMenuItem1ActionPerformed(evt);
            }
        });
        jMenu5.add(jMenuItem1);

        GUI_Menu.add(jMenu5);

        jMenu6.setText("Support");

        Item_Relaod_APP_Database.setText("Reload App Database");
        Item_Relaod_APP_Database.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Item_Relaod_APP_DatabaseActionPerformed(evt);
            }
        });
        jMenu6.add(Item_Relaod_APP_Database);

        GUI_Menu.add(jMenu6);

        setJMenuBar(GUI_Menu);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 847, Short.MAX_VALUE)
                    .addComponent(GUI_Scroll_Pane_Log_Area))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 344, Short.MAX_VALUE)
                .addGap(18, 18, 18)
                .addComponent(GUI_Scroll_Pane_Log_Area, javax.swing.GroupLayout.PREFERRED_SIZE, 102, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void Item_CheckPoint_MGMT_API_ConnectionActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_MGMT_API_ConnectionActionPerformed
      
        GUI_CheckPoint_MGMT_API_Login();
        
        
    }//GEN-LAST:event_Item_CheckPoint_MGMT_API_ConnectionActionPerformed

    private void Item_CheckPoint_Get_Access_Control_LayerActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_Get_Access_Control_LayerActionPerformed
        
        GUI_CheckPoint_MGMT_Get_Access_Control_Layer();
        
    }//GEN-LAST:event_Item_CheckPoint_Get_Access_Control_LayerActionPerformed

    private void Item_CheckPoint_MGMT_API_ExitActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_MGMT_API_ExitActionPerformed
       
        
    }//GEN-LAST:event_Item_CheckPoint_MGMT_API_ExitActionPerformed

    private void Item_CheckPoint_Human_ViewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_Human_ViewActionPerformed
      
        show_human_view();
        
    }//GEN-LAST:event_Item_CheckPoint_Human_ViewActionPerformed

    private void Item_CheckPoint_Machine_ViewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_Machine_ViewActionPerformed
      
        show_machine_view();
                
                
    }//GEN-LAST:event_Item_CheckPoint_Machine_ViewActionPerformed

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        
        show_network_object_exporer();
    }//GEN-LAST:event_jMenuItem1ActionPerformed

    private void Item_CheckPoint_Get_Firewall_FactsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_CheckPoint_Get_Firewall_FactsActionPerformed
        
        get_facts_directory();
        
    }//GEN-LAST:event_Item_CheckPoint_Get_Firewall_FactsActionPerformed

    private void jMenuItem2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem2ActionPerformed
      
        load_ruleset_from_file();
    }//GEN-LAST:event_jMenuItem2ActionPerformed

    private void Item_Relaod_APP_DatabaseActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Item_Relaod_APP_DatabaseActionPerformed
        
        GUI_CheckPoint_MGMT_Reload_APP_Database();
                
    }//GEN-LAST:event_Item_Relaod_APP_DatabaseActionPerformed

    public void load_ruleset_from_file()
    {
        try
        {
            
            JFileChooser file_chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
            file_chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            //file_chooser.showOpenDialog(null);
            String filaaae = "E:\\Dev\\jBlackWall\\BlackWall\\DATA\\FW-WAW-01";
            
            log_handler.log_in_gui("Loading ruleset from file: " + filaaae + "\n" );
            //log_handler.log_in_gui("Loading ruleset from file: " + file_chooser.getSelectedFile().toString() + "\n" );

            
            new Thread(new Runnable() {
                     public void run() {
           
            
                  CheckPoint_Management_API_handler.Mgmt_File_Process_Ruleset(config_file_processor.json_ruleset_from_file(filaaae), "FW-WAW-01");
                  
                  config_file_processor.json_objects_from_file(filaaae);
                  
                  //config_file_processor.json_objects_from_file(file_chooser.getSelectedFile().toString());
             
                   }
            }).start();
        
        }
        catch (Exception e)
        {
             log_handler.log_in_gui("(LRFL) ERROR: " + e.getLocalizedMessage() , "100358" , "" );
        }
       
    }
    
    
    public void get_facts_directory()
    {
     
        
        try
        {
        
            JFileChooser file_chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
            file_chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            //file_chooser.showOpenDialog(null);
            //firewall_local_facts.facts_directory = file_chooser.getSelectedFile().toString();
            firewall_local_facts.facts_directory = "E:\\Dev\\FIREWALL";
            firewall_local_facts.start_processing();

          

        
        }
        catch (Exception e)
        {
             log_handler.log_in_gui("(GFD) ERROR: " + e.getLocalizedMessage() , "301810" , "" );
        }
        
    }
    
    public void show_network_object_exporer()
    {
 
        CheckPoint_Management_API_handler.show_network_object_dictionary();
        
    }
    
    
    public void show_machine_view()
    {
        
            for (int i = 0 ;  i < GUI_Ruleset_Table.getColumnCount() ; i++)
            {

                show_column(i);


            }

            hide_column("Enabled");
            hide_column("Source");
            hide_column("Destination");
            hide_column("Service");
            hide_column("TP Profile");
            hide_column("Highlight");
            
    }
    
    
    public void show_human_view()
    {
            for (int i = 0 ;  i < GUI_Ruleset_Table.getColumnCount() ; i++)
            {

                show_column(i);


            }
        
        
            hide_column("Enabled");
            hide_column("Src Machine");
            hide_column("Src Zone");
            hide_column("Dst Machine");
            hide_column("Dst Zone");
            hide_column("Srv Machine");
            hide_column("TP Profile");
            hide_column("Highlight");
    }
    
    public void GUI_Exit()
    {
        
        
        
        
    }
    
    public void GUI_CheckPoint_MGMT_Reload_APP_Database()
    {
            
            if (!CheckPoint_Management_API_handler.API_SID_Return())
            {
                log_handler.log_in_gui("We do not have connection yet. Please use Connect -> Management API \n", "" , "");
                return;
                
            }
        
            if (get_layers_in_progres == true)
            {
       
               try
               {
                   
                    CheckPoint_Management_API_STOP_Window stop_window = new CheckPoint_Management_API_STOP_Window(this, rootPaneCheckingEnabled);
                    stop_window.set_info("Already In Progress", "Please wait till previous action will finish");
                    stop_window.setLocationRelativeTo ( null );
                    stop_window.setVisible(true);

               

                    stop_window.dispose();
                    return;
                    
               }
               catch (Exception e)
                {

                   log_handler.log_in_gui("(GCMRAD) ERROR: " + e.getLocalizedMessage() , "181445" , "" );
                   return;

                }
            }
         
            
            if ( !CheckPoint_Management_API_handler.API_Still_Connected())
            {
                // not connected

                CheckPoint_Management_API_handler.API_Login();


            }
            
                 
           new Thread(new Runnable() {
             public void run() {
           
                 
                  CheckPoint_Management_API_handler.Mgmt_API_Build_App_Database();
                 
                 
             }
           }).start();
            
                       
                       
        
    }
    
    
    
    public void GUI_CheckPoint_MGMT_Get_Access_Control_Layer()
    {
            
            if (!CheckPoint_Management_API_handler.API_SID_Return())
            {
                log_handler.log_in_gui("We do not have connection yet. Please use Connect -> Management API \n", "" , "");
                return;
                
            }
        
        
            if (get_layers_in_progres == true)
            {
       
               try
               {
                   
                    CheckPoint_Management_API_STOP_Window stop_window = new CheckPoint_Management_API_STOP_Window(this, rootPaneCheckingEnabled);
                    stop_window.set_info("Already In Progress", "Please wait till previous action will finish");
                    stop_window.setLocationRelativeTo ( null );
                    stop_window.setVisible(true);

               

                    stop_window.dispose();
                    return;
                    
               }
               catch (Exception e)
                {

                   log_handler.log_in_gui("(GCMGACL) ERROR: " + e.getLocalizedMessage() , "319308" , "" );
                   return;

                }
            }
        

            if ( !CheckPoint_Management_API_handler.API_Still_Connected())
            {
                // not connected

                CheckPoint_Management_API_handler.API_Login();


            }
            
            
           String show_layers_body = CheckPoint_Management_API_handler.Mgmt_API_body_builder_show_layers();
           String show_layers_respond = CheckPoint_Management_API_handler.Mgmt_API_REST_Call("show-access-layers", show_layers_body);
           
           String show_gateways_body = CheckPoint_Management_API_handler.Mmgt_API_body_builder_empty_body();
           String show_gateways_respond = CheckPoint_Management_API_handler.Mgmt_API_REST_Call("show-simple-gateways", show_gateways_body);
           
           String show_clusters_body = CheckPoint_Management_API_handler.Mmgt_API_body_builder_empty_body();
           String show_clusters_respond = CheckPoint_Management_API_handler.Mgmt_API_REST_Call("show-simple-clusters", show_clusters_body);
     
           CheckPoint_Management_API_Select_Layer_Window layer_window = new CheckPoint_Management_API_Select_Layer_Window(this, rootPaneCheckingEnabled);
           layer_window.log_handler_merge(log_handler);
           
           layer_window.load_combo_box_layer(show_layers_respond);
           layer_window.load_combo_box_gateways(show_gateways_respond);
           layer_window.load_combo_box_gateways(show_clusters_respond);
           
           layer_window.setLocationRelativeTo ( null );
           layer_window.setVisible(true);
           
           
           String selected_layer =  layer_window.get_selected_layers();
           String selected_firewall = layer_window.get_selected_firewall();
           boolean with_inline_layers = layer_window.get_with_inline_layers();
      
           
          
           new Thread(new Runnable() {
             public void run() {
           
                get_layers_in_progres = true;
                
                if ( with_inline_layers == true)
                {
                    
                    log_handler.log_in_gui("Reading layer '" + selected_layer  +"' (with inline layers) on '" + selected_firewall + "' \n" , "" , "");
                    
                }
                else
                {
                    log_handler.log_in_gui("Reading layer '" + selected_layer  +"' on '" + selected_firewall + "' \n" , "" , "");
                    
                }
                
                CheckPoint_Management_API_handler.Mgmt_API_Process_Ruleset(selected_layer, true, "" , with_inline_layers, selected_firewall);
                get_layers_in_progres = false;
                
                if ( with_inline_layers == true)
                {
                    
                    log_handler.log_in_gui("Reading layer '" + selected_layer  +"' (with inline layers) on '" + selected_firewall + "'. Completed \n" , "" , "");
                    
                }
                else
                {
                    log_handler.log_in_gui("Reading layer '" + selected_layer  +"' on '" + selected_firewall + "'. Completed \n" , "" , "");
                    
                } 
                
                log_handler.log_in_gui("Saving database. \n" , "" , "");
                CheckPoint_Management_API_handler.get_ruleset();
          
                config_file_processor = new Config_File_Procesor();        
                config_file_processor.log_handler = log_handler;
                config_file_processor.json_ruleset_to_file(CheckPoint_Management_API_handler.get_ruleset(), selected_firewall);
               
                config_file_processor.json_objects_to_file(Object_Processor_Handler.get_network_object_set(), selected_firewall);
                
               
                System.out.println("SIZE: " + CheckPoint_Management_API_handler.get_ruleset().size());
             }
           }).start();
        
        
    }
    
   
    public void GUI_CheckPoint_MGMT_API_Login()
    { 
        
      CheckPoint.Windows.CheckPoint_Management_API_Login_Window GUI_Check_Point_New_Connect= new CheckPoint_Management_API_Login_Window(this, rootPaneCheckingEnabled);
  //    CheckPoint.CheckPoint_Management_API_Window GUI_Check_Point_New_Connect = new CheckPoint_Management_API_Window();
      GUI_Check_Point_New_Connect.setLocationRelativeTo ( null );
      GUI_Check_Point_New_Connect.setVisible(true);
      
      
       
      
      if (GUI_Check_Point_New_Connect.get_connect_action())
      {
       
          // connection 
                    
           String Management_IP = GUI_Check_Point_New_Connect.get_management_ip();
           String Management_Port = GUI_Check_Point_New_Connect.get_management_port();
           String Username = GUI_Check_Point_New_Connect.get_username();
           char[] Password = GUI_Check_Point_New_Connect.get_password();
           boolean IgnoreCert = GUI_Check_Point_New_Connect.get_ignore_cert();
           
           CheckPoint_Management_API_handler.set_connection_paramters(Management_IP, Management_Port, Username, Password, IgnoreCert);
           
          
           
           new Thread(new Runnable() {
                public void run() {

                   get_layers_in_progres = true;
                   CheckPoint_Management_API_handler.API_Login();
                   get_layers_in_progres = false;

                }
           }).start();
        
           
      }
      
      
      GUI_Check_Point_New_Connect.dispose();
        
        
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
            java.util.logging.Logger.getLogger(CheckPoint_MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(CheckPoint_MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(CheckPoint_MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(CheckPoint_MainWindow.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new CheckPoint_MainWindow().setVisible(true);
                
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextPane GUI_Log_Area;
    private javax.swing.JMenuBar GUI_Menu;
    private javax.swing.JTable GUI_Ruleset_Table;
    private javax.swing.JScrollPane GUI_Scroll_Pane_Log_Area;
    private javax.swing.JMenuItem Item_CheckPoint_Get_Access_Control_Layer;
    private javax.swing.JMenuItem Item_CheckPoint_Get_Firewall_Facts;
    private javax.swing.JMenuItem Item_CheckPoint_Human_View;
    private javax.swing.JMenuItem Item_CheckPoint_MGMT_API_Connection;
    private javax.swing.JMenuItem Item_CheckPoint_MGMT_API_Exit;
    private javax.swing.JMenuItem Item_CheckPoint_Machine_View;
    private javax.swing.JMenuItem Item_CheckPoint_TP_View;
    private javax.swing.JMenuItem Item_Relaod_APP_Database;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenu jMenu3;
    private javax.swing.JMenu jMenu4;
    private javax.swing.JMenu jMenu5;
    private javax.swing.JMenu jMenu6;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JMenuItem jMenuItem2;
    private javax.swing.JScrollPane jScrollPane1;
    // End of variables declaration//GEN-END:variables
}
