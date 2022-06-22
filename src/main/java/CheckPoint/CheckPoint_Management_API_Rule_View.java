/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint;

import General.Log;
import java.awt.Color;
import java.awt.Component;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import javax.swing.JTable;
import javax.swing.border.Border;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;

/**
 *
 * @author Maciej
 */
public class CheckPoint_Management_API_Rule_View 
{
    JTable GUI_Ruleset_Table;
    public Log log_handler; 
    
    
    int default_row_hight = 16;
     Map<String, Integer > table_columns ;
    
    
    
    
    public void merge_jtable(JTable GUI_Ruleset_Table,  Map<String, Integer > table_columns)
    {
        
        this.GUI_Ruleset_Table = GUI_Ruleset_Table;
        
        int col_count = GUI_Ruleset_Table.getColumnCount();
        CustomRenderer cst_render = new CustomRenderer();

        
        
        for (int i = 1 ; i < col_count ; i++)
        {
            
                 GUI_Ruleset_Table.getColumnModel().getColumn(i).setCellRenderer(cst_render);
   
            
        }
        
         GUI_Ruleset_Table.getColumnModel().getColumn(0).setCellRenderer(new CustomRenderer_No_Column());
        
         GUI_Ruleset_Table.setRowSelectionAllowed(true);

        
    }
  
    public int calculate_row_high(CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule)
    {
         // kalkulacja wysokosci wiersza
         // do poprawy
        
          int obj_count_src = current_rule.source.length;  
          int obj_count_dst = current_rule.destination.length;
          int obj_count_service = current_rule.service.length;
          
          if (current_rule.source_negate == true)
          {
              
              obj_count_src = obj_count_src + 2;
              
          }
          
          if (current_rule.destination_negate == true)
          {
              
              obj_count_dst = obj_count_dst + 2;
              
          }
          
          if (current_rule.service_negate == true)
          {
              
              obj_count_service = obj_count_service + 2;
              
          }
            
          int obj_count = 2;   // from hitcount
          
          
          if (obj_count < obj_count_src )
          {
              
              obj_count = obj_count_src;
              
          }
          
          if (obj_count < obj_count_dst )
          {
              
              obj_count = obj_count_dst;
              
          }
          
          if (obj_count < obj_count_service )
          {
              
              obj_count = obj_count_service;
     
          }
          
          return   (default_row_hight * obj_count) + 8;
          
        
    }
    
    
    
    public void prepare_rule_view(CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule, boolean  add_sleep_time)
    {
        
        try
        {
        
           int   row_hight = calculate_row_high(current_rule);
           DefaultTableModel GUI_Ruleset_Table_Model = (DefaultTableModel) GUI_Ruleset_Table.getModel();
          

               
           GUI_Ruleset_Table_Model.addRow(
           
                   new Object[]
                   
                   { prepare_cell_view_rule_number( current_rule.number, current_rule.enabled ) ,                // number
                     Boolean.toString(current_rule.enabled) ,               // enabled
                     prepare_cell_view_hits(current_rule),                // hits 
                     current_rule.name,  // name
                     prepare_cell_view_network(current_rule.source , current_rule.source_negate),                // source
                     prepare_cell_view_network_range(current_rule.source_range, current_rule.source_negate),                // source machine
                     "",                // source zone
                     prepare_cell_view_network(current_rule.destination , current_rule.destination_negate),                // destination
                     prepare_cell_view_network_range(current_rule.destination_range, current_rule.destination_negate),                // destination machine
                     "",                // destination zone
                     prepare_cell_view_service(current_rule.service, current_rule.service_negate),                // service
                     prepare_cell_view_service_range(current_rule.service_range , current_rule.service_negate),                // service machine
                     prepare_cell_view_content(current_rule.content, current_rule.content_negate, current_rule.content_direction),                // content 
                     prepare_cell_view_time(current_rule.time),                // time
                     prepare_cell_view_vpn(current_rule.vpn),                // vpn
                     prepare_cell_view_action(current_rule.action , current_rule.action_layer, current_rule.action_usercheck , current_rule.action_captive_portal)   ,                // action
                     prepare_cell_view_track(current_rule),                // track 
                     ""  ,                // tp profile
                     current_rule.comment,                // comment
                     prepare_cell_view_install_on(current_rule.install_on),
                    prepare_cell_metainfo(current_rule.rule_creator, current_rule.rule_creation_time, current_rule.rule_modifier, current_rule.rule_modify_time, current_rule.custom_filed1, current_rule.custom_filed2, current_rule.custom_filed3)
                   
                   });
            
               if(add_sleep_time)
               {
                    Thread.sleep(100);
               }

               int last_row = GUI_Ruleset_Table.getRowCount();
               GUI_Ruleset_Table.setRowHeight(last_row - 1, row_hight);
            
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui("(PRV) Error: " + e.getMessage(), "82886" , "");
            
        }
        
        
    }
    
  
    
    public void prepare_section_view(CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule)
    {
            
        try
        {
            
 
           DefaultTableModel GUI_Ruleset_Table_Model = (DefaultTableModel) GUI_Ruleset_Table.getModel();
           GUI_Ruleset_Table_Model.addRow(new Object[]{ "",  "" , "", current_rule.name });
      
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui("(PSV) Error: " + e.getMessage(), "47087", current_rule.name);
            
            
        }
 
    }

    
    
class CustomRenderer extends DefaultTableCellRenderer 
{
private static final long serialVersionUID = 6703872492730589499L;
public  Map<String, Integer > table_columns_test ;

    public int get_column_index_by_name(String column)
    {
        
        return table_columns_test.get(column);
        
    }


    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
    {
    
        try
        {
        
        
        table_columns_test = new HashMap<String,Integer>();
        Component cellComponent = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        Border b;
        
    
        
        if (value!= null)
        {
      
            int col_count = table.getColumnModel().getColumnCount();
            
            for (int i = 0 ; i < col_count; i ++)
            {
                
                table_columns_test.put(table.getColumnModel().getColumn(i).getHeaderValue().toString(), i);
            
            }
            
          
            
            String text = "";    

            String column_name = table.getColumnModel().getColumn(column).getHeaderValue().toString();
            if (column_name.equals("Source") || column_name.equals("Destination") || column_name.equals("Service"))
            {

                text = value.toString().replaceFirst("</html>" , "").replaceFirst("<html>", "<html> Human view: <br/>") + "<br/>" ;// + table.getValueAt(row, column + 1).toString().replaceFirst("<html>" , "Machine view: <br/>");

                if (column_name.equals("Source"))
                {
                    int col = get_column_index_by_name("Src Machine");
                    text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "Machine view: <br/>");
                }
                
                if (column_name.equals("Destination"))
                {
                    int col =  get_column_index_by_name("Dst Machine");
                    text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "Machine view: <br/>");
                }
                if (column_name.equals("Service"))
                {
                   int col = get_column_index_by_name("Srv Machine");
                   text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "Machine view: <br/>");
                    
                }
                
            }
            if (column_name.equals("Src Machine") || column_name.equals("Dst Machine") || column_name.equals("Srv Machine"))
            {

                

                if (column_name.equals("Src Machine"))
                {
                    int col = get_column_index_by_name("Source");
                    text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "<html> Human view: <br/>").replaceFirst("</html>" , "<br/>");
                }
                
                if (column_name.equals("Dst Machine"))
                {
                    int col =  get_column_index_by_name("Destination");
                    text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "<html> Human view: <br/>").replaceFirst("</html>" , "<br/>");
                }
                if (column_name.equals("Srv Machine"))
                {
                   int col = get_column_index_by_name("Service");
                   text += table.getValueAt(row, col).toString().replaceFirst("<html>" , "<html> Human view: <br/>").replaceFirst("</html>" , "<br/>");
                    
                }
                
                text += value.toString().replaceFirst("<html>", "Machine view: <br/>") + "<br/>" ;// + table.getValueAt(row, column + 1).toString().replaceFirst("<html>" , "Machine view: <br/>");

                
                
                
            } 
      
            if(text.equals(""))
            {

                text = value.toString();
            }

            
          setToolTipText(text);
          
        }
            
       
        
        if(table.getValueAt(row, 0) == "")
        {
 
            cellComponent.setBackground(Color.YELLOW);
           
        } 
        else 
        {
            

            
            cellComponent.setBackground(Color.WHITE);
    
        }
        return cellComponent;
        
        
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui(("(GTCRC) Error: " + e.getMessage()), "954024" , "");
            return null;

        }
    }
}



class CustomRenderer_No_Column extends DefaultTableCellRenderer 
{
private static final long serialVersionUID = 6703872492730589499L;

    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
    {
        Component cellComponent = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        Border b;
        
        
        try
        {
        
            if(table.getValueAt(row, 0) == "")
            {

                cellComponent.setBackground(Color.YELLOW);

            } 
            else 
            {



                cellComponent.setBackground(Color.lightGray);
                

                
                
            }
            

           
            return cellComponent;
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui(("(GTCRC) Error: " + e.getMessage()), "24773" , "");
            return cellComponent;

        }
    }
}



public String prepare_cell_view_network (CheckPoint_Management_API_Rule_Processor.Object_network network[] , boolean negate_object)
        {
           
            
            String current_name = "";
            String current_type = "";
            
            
            try
            {
            
            

                String return_string = "";

                return_string += "<html> ";
              //  return_string += "<img src=\"file:///E:/Dev/jBlackWall/BlackWall/target/classes/../../aaaa.png\" width=\"12\" height=\"12\" >";


                if (negate_object == true)
                {

                    return_string += "==== Negate ====<br/>";

                }

                int last = network.length ;
            
                // ikonki, symbole typow obiektow
                
                for ( int i = 0 ; i < last  ; i++)
                {
                    current_name = network[i].name;
                    current_type = network[i].type;
                    
                    if (network[i].type.equals("host"))
                    {

                        return_string +=  " <b>[H] </b>";

                    }

                    if (network[i].type.equals("network"))
                    {

                        return_string +=  " <b>[N] </b>";
                    }

                    if (network[i].type.equals("group"))
                    {

                        return_string +=  " <b>[G] </b>";
                    }
                    
                    if (network[i].type.equals("group-with-exclusion"))
                    {

                        return_string +=  " <b>[GWE] </b>";
                    }                

                    if (network[i].type.equals("access-role"))
                    {

                        return_string +=  " <b>[U] </b>";
                    }
                    

                    if (network[i].type.equals("data-center-object"))
                    {

                        return_string +=  " <b>[M] </b>";
                    }
                    
        
                    if (network[i].type.equals("wildcard"))
                    {

                        return_string +=  " <b>[W] </b>";
                    }

                    if (network[i].type.equals("address-range"))
                    {

                        return_string +=  " <b>[R] </b>";
                    }                    

                    if (network[i].type.equals("CpmiAnyObject"))
                    {

                        return_string +=  " <b>[*] </b>";
                    }
                    
                     if (network[i].type.equals("CpmiLogicalServer"))
                    {

                        return_string +=  " <b>[LS] </b>";
                    }

                    if (network[i].type.equals("CpmiGatewayPlain"))
                    {

                        return_string +=  " <b>[IO] </b>";
                    }

                    if (network[i].type.equals("CpmiOseDevice"))
                    {

                        return_string +=  " <b>[OSE] </b>";
                    }           
                    
                    
                    if (network[i].type.equals("security-zone"))
                    {

                        return_string +=  " <b>[Z] </b>";
                    }
                    
                    if (network[i].type.equals("checkpoint-host"))
                    {

                        return_string +=  " <b>[CP] </b>";
                    }          

                    if (network[i].type.equals("simple-gateway"))
                    {

                        return_string +=  " <b>[CP] </b>";
                    }
                                        
                    if (network[i].type.equals("simple-cluster"))
                    {

                        return_string +=  " <b>[CP] </b>";
                    }
                           
                    
                    if (network[i].type.equals("dns-domain"))
                    {

                        return_string +=  " <b>[DD] </b>";
                    }
                           
                    if (network[i].type.equals("dynamic-object"))
                    {

                        return_string +=  " <b>[DO] </b>";
                    }
                                           
                    if (network[i].type.equals("updatable-object"))
                    {

                        return_string +=  " <b>[UO] </b>";
                    }
                     
                    return_string += network[i].name;
                    return_string +=  " <br/>";


                }        

                if (negate_object == true)
                {

                    return_string += "================<br/> ";

                }
                
                return_string += "</html> ";
                return return_string;


            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVN) Error: " + e.getMessage(), "69070" , current_name + " " + current_type );
                return "";
                
            }
            
            
            
        }

        public String  prepare_cell_view_rule_number( String number, boolean  enabled)
          {
              
            try
            {
              
                String return_string = "";

                return_string += "<html> ";

                if (enabled == true)
                {

                    return_string += "<b>" + number + "</b>" ;


                } 
                else
                {
                     return_string += "" + number + "<br/> (Disabled)";

                }
                
            
                return_string += "<br/> ";
                return_string += "</html> ";

                return return_string;

            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVRN) Error: " + e.getMessage(), "986105" , number );
                return "";
                
            }
            
            
            
          }




        public String prepare_cell_view_hits(CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule)
        {
            
            String return_string = "";
            
            try
            {
                

                return_string += "<html> ";

                return_string += current_rule.hits_value + "<br/>";
                return_string += current_rule.hits_percent + "<br/>" ;
                return_string += current_rule.hits_level;

                return_string += "</html> ";

                return return_string;
            
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVRH) Error: " + e.getMessage(), "986105" , return_string );
                return "";
                
            }
        }

        
        public String prepare_cell_view_action(String action, String action_layer , String action_usercheck, boolean action_captive_portal)
        {
             String return_string = "";
             return_string += "<html> ";
            
           
             try
             {

                if (action.equals("Inner Layer"))
                {
                    return_string += "Inline Layer => <br/> " + action_layer;

                }
                else
                {

                     return_string += action + "<br/>";

                }    


                if ( action_captive_portal == true )
                {

                     return_string += " (Captive) ";
                }

                if (!action_usercheck.equals(""))
                {

                    return_string += " (" + action_usercheck + ") ";

                }

                return_string += "</html> ";

                return return_string;
             }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVA) Error: " + e.getMessage(), "677379" , return_string );
                return "";
                
            }          
            
        }
        

        public String prepare_cell_view_service_range(CheckPoint_Management_API_Rule_Processor.Object_service_range[]  service_range , boolean  content_negate)
        {

                String current_name = "";
                String current_type = "";
                String return_string = "";
                int supres_view_count = 0;
                
                Set<String> suppressed_services = new HashSet<String>();
                
                try
                {
                    
                    if ((service_range == null) || (service_range.length == 0))
                    {
                      //  return "Null (Should not be visible)";
                        
                    }
                                      
                    return_string += "<html> ";

                    
                    if (content_negate == true)
                    {

                        return_string += "==== Negate ====  <br/>";

                    }
              
                   int last = service_range.length;
            
                    for ( int i = 0 ; i < last  ; i++)  
                    {
                        
                        
                        if(service_range[i].suppres_view == true)
                        {
                            
                            suppressed_services.add(service_range[i].app_service);
               
                            supres_view_count++;
                            continue;
                            
                        }

                        if (service_range[i].type != null)
                        {
                            if (service_range[i].type.equals("CpmiAnyObject"))
                            {
                                
                                
                                 return_string +=  "Any";
                                 return_string += "<br/>";
                                 
                                 
                            }
                            
                            
                            if (service_range[i].type.equals("service-tcp"))
                            {

                                 return_string +=  "TCP " + service_range[i].start + " - " + service_range[i].end  + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }
                            
                            if (service_range[i].type.equals("service-udp"))
                            {

                                 return_string +=  "UDP " + service_range[i].start + " - " + service_range[i].end  + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }

                            if (service_range[i].type.equals("service-icmp"))
                            {

                                 return_string +=  "ICMP Type " + service_range[i].icmptype   + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }
                            
                            
                            if (service_range[i].type.equals("service-other"))
                            {

                                 return_string +=  "Other IP:" + service_range[i].protocol   + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }
                            
                            
                            if (service_range[i].type.equals("service-rpc"))
                            {

                                 return_string +=  "RPC Service" + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }
                            
                            if (service_range[i].type.equals("service-dce-rpc"))
                            {

                                 return_string +=  "DCE RPC Service" + " ("+ service_range[i].name + ")";
                                 return_string += "<br/>";
                                 
                            }
                  
                            if (service_range[i].type.equals("application-site") || service_range[i].type.equals("application-site-category"))
                            {
                                    
                   
                                  if (service_range[i].app_service_type.equals("Other"))
                                  {
                                     return_string +=  service_range[i].name + " (IP:" + service_range[i].protocol + ")";
                                     
                                     if (service_range[i].app_service_nagate == true)
                                     {
                                         
                                         return_string += " - Negate ";
                                     }
                                     
                                     return_string += "<br/>";
                                     continue;
                                  }
                                 
                                  if (service_range[i].app_service_type.equals("DCE-RPC"))
                                  {
                                     return_string +=  service_range[i].name + " (" + service_range[i].app_service_type + ")";
                                     
                                     if (service_range[i].app_service_nagate == true )
                                     {
                                         
                                         return_string += " - Negate ";
                                     }
                                     
                                     
                                     return_string += "<br/>";
                                     continue;
                                  }
                                  
                                  
                                  if (service_range[i].app_service_type.equals("Any"))
                                  {
                                     return_string +=  service_range[i].name;
                                     
                                     if (service_range[i].app_service_nagate == true )
                                     {
                                         
                                         return_string += " - Negate ";
                                     }
                                     
                                     
                                     return_string += "<br/>";
                                     continue;
                                  }
                                  
                   
                                  

                                    return_string +=  service_range[i].name + " (" + service_range[i].app_service_type + " " + service_range[i].start + " - " + service_range[i].end  + ")";

                                    if (service_range[i].app_service_nagate == true)
                                    {

                                        return_string += " - Negate ";
                                    }


                                    return_string += "<br/>";


                            
  
                            }
                            
                            
                        }
                        
                        
                        

                    }
               
                  
                    
               if (supres_view_count > 0)     
               {
                   return_string += "Applications on following services:  <br/>";
                   
                   Iterator iter =   suppressed_services.iterator();
                   
                   int i = 0;
                   
                   while(iter.hasNext())
                   {
                       
                       String service = (String) iter.next();
                       
                       return_string += " " + service + " ";
                       i++;
                       
                       if (i >= 10)
                       {
                           i = 0;
                           return_string += " <br/>"; 
                       }
                       
                   }
                   
                    return_string += " <br/>"; 
                     
               }     
                   
               if (content_negate == true)
               {

                   return_string += "==== Negate ====  <br/>";

               }
                    
                    
                    return_string += "</html> ";
                   
                    
                    
                    
                    return return_string;
                    
                }
                catch (Exception e)
                {
                                    
                    log_handler.log_in_gui("(PCVSR) Error:" + e.getMessage() +  e.getLocalizedMessage() + return_string, "183449", return_string);
                    return "";

                }
        }


        
        public String prepare_cell_view_network_range(CheckPoint_Management_API_Rule_Processor.Object_network_range[] source_range , boolean  content_negate)
        {
            String return_string = "";
            
            try
            {
                return_string += "<html> ";

               if (content_negate == true)
               {

                   return_string += "==== Negate ====  <br/>";

               }



                int last = source_range.length;

                for ( int i = 0 ; i < last  ; i++)  
                {

                    if (source_range[i].type != null)
                    {


                        if (source_range[i].type.equals("host"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

                       if (source_range[i].type.equals("CpmiGatewayPlain"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

        
                        if (source_range[i].type.equals("CpmiLogicalServer"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name + " -> " +   source_range[i].logial_server_group  +")";
                            return_string += "<br/>";
                        }            
        
        
                        if (source_range[i].type.equals("CpmiOseDevice"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }
                        if (source_range[i].type.equals("network"))
                        {


                            return_string +=  source_range[i].network + "/" + source_range[i].network_subnet + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("wildcard"))
                        {

                            return_string +=  source_range[i].network + "/" + source_range[i].network_subnet + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("address-range"))
                        {

                            return_string +=  source_range[i].range_start + "-" + source_range[i].range_end + " (" + source_range[i].name +")";
                            return_string += "<br/>";

                        }

                        if (source_range[i].type.equals("group"))
                        {

                            return_string +=  " Should not be visible";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("access-role"))
                        {

                            return_string +=  source_range[i].object_count + " users (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("data-center-object"))
                        {

                            return_string +=  source_range[i].object_count + " machines (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }


                        if (source_range[i].type.equals("CpmiAnyObject"))
                        {

                            return_string +=  "0.0.0.0/0 (Any)";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("security-zone"))
                        {


                            return_string +=  source_range[i].network + "/" + source_range[i].network_subnet + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }

                        if (source_range[i].type.equals("checkpoint-host"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";       
                        }         

                        if (source_range[i].type.equals("simple-gateway"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";      
                        }

                        if (source_range[i].type.equals("simple-cluster"))
                        {

                            return_string +=  source_range[i].address + " (" + source_range[i].name +")";
                            return_string += "<br/>";
                        }


                        if (source_range[i].type.equals("dns-domain"))
                        {

                            if (source_range[i].suppres_view == true)
                            {

                            }   
                            else
                            {    
                              String fixed_name = "";

                               fixed_name =  source_range[i].name;

                               return_string +=  fixed_name + " - " + source_range[i].object_count + " Ranges <br/>";


                            }
                        }

                        if (source_range[i].type.equals("dynamic-object"))
                        {

                            if (source_range[i].suppres_view == true)
                            {

                            }   
                            else
                            {

                              String fixed_name = "";

                              //fixed_name =  source_range[i].name;
                              fixed_name =  source_range[i].name.substring(0, source_range[i].name.indexOf("."));
                              return_string +=  fixed_name + " - " + source_range[i].object_count + " Ranges <br/>";


                            }   
                        }

                        if (source_range[i].type.equals("updatable-object"))
                        {

                            if (source_range[i].suppres_view == true)
                            {

                            }   
                            else
                            {    
                                 String fixed_name = "";

                              if (!source_range[i].name.contains("."))
                              {

                                  // przejsciowe. usunac po ogarnieciu nowej metody przy dst.


                                  fixed_name =  source_range[i].name;
                              }
                              else
                              {
                                // loose dot and range number
                                fixed_name =  source_range[i].name.substring(0, source_range[i].name.indexOf("."));

                              }
                               return_string +=  fixed_name + " - " + source_range[i].object_count + " Ranges <br/>";


                            }
                        }


                        if (source_range[i].extra_options == 1)
                        {

                             return_string += " <b>(Excluded)</b>";
                             return_string += "<br/>";
                        }




                    }
    
            }

            
            if (content_negate == true)
            {

                return_string += "==== Negate ====  <br/>";

            }
            
            return_string += "</html> ";
            return return_string;  
            
            } 
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVNR) Error:" + e.getMessage() +  e.getLocalizedMessage() + return_string, "72827", return_string);
                return "";
                
            }
            
        }
        
   
         public String prepare_cell_view_content(CheckPoint_Management_API_Rule_Processor.Object_content[] content, boolean content_negate, String  content_direction )
         {
             
             String return_string = "";
             
             try
                 
             {
                return_string += "<html> ";

               if (content_negate == true)
               {

                   return_string += "==== Negate ====  <br/>";

               }

               return_string += "(Direction: " + content_direction + ") ";

               return_string += "<br/>";


               int last = content.length;

               for ( int i = 0 ; i < last ; i++)  
               {

                   if (content[i].name.equals("Any"))
                   {

                      return_string += "<b> [*] </b> " + content[i].name;
                      return_string += "<br/>";


                   }
                   else
                   {

                   return_string += "<b> [C] </b> " + content[i].name;
                   return_string += "<br/>";

                   }
               }


                if (content_negate == true)
               {

                   return_string += "==== Negate ====  <br/>";

               }

                return return_string;

            } 
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVC) Error:" + e.getLocalizedMessage(), "373020", return_string);
                return "";
                
            }
             
         }
             
         
        public String prepare_cell_view_install_on (CheckPoint_Management_API_Rule_Processor.Object_install_on[] install_on)
        {
            
            String return_string = "";

            try
            {

                return_string += "<html> "; 


                int last = install_on.length;
            

                for ( int i = 0 ; i < last ; i++)  
                {

                    if (install_on[i].name.equals("Policy Targets"))
                    {
                        return_string += "<b>[*] </b> Policy Targets" ;
                        return_string += "<br/>";

                    }
                    else
                    {
                        return_string += "<b>[CP]</b> " + install_on[i].name;
                        return_string += "<br/>";
                    }


                }

                return_string += "</html> ";

                return return_string;
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVIO) Error:" + e.getLocalizedMessage(), "570558", return_string);
                return "";
                
            }
        } 
          
                 
        public String prepare_cell_metainfo(String creator, Long creation_time, String modifier, Long modify_time, String custom1, String custom2, String custom3)
        {
            String return_string = "";
            
            try
            {
                    return_string += "<html> "; 
                    
                    Date date = new Date(creation_time);
                    date.toString();
                    
                    return_string += "<b>C: </b>" + creator + " " + date.toString() + "<br/>";
                    
                    
                    date = new Date(modify_time);
                    date.toString();
                    
                    
                    return_string += "<b>M: </b>" + modifier + " " + date.toString() + "<br/>";
                    
                    if (custom1.length() != 0)
                    {
                        
                         return_string += "<b>Rule Info: </b>" + custom1  + "<br/>";
                         
                    }
                    
                    if (custom2.length() != 0)
                    {
                        
                         return_string += "<b>Ticket: </b>" + custom2  + "<br/>";
                        
                    }
                    
                    if (custom3.length() != 0)
                    {
                         return_string += "<b>Requester: </b>" + custom3  + "<br/>";
                        
                    }
                    
                    return_string += "</html> ";
                
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCMI) Error:" + e.getLocalizedMessage(), "593487", return_string);
                return "";
                
            }
            
            return return_string;
        }
                
                
        public String prepare_cell_view_time(CheckPoint_Management_API_Rule_Processor.Object_time[] time)
        {
            String return_string = "";

            try
            {
                   
            
               return_string += "<html> "; 
            
               int last = time.length;
            
              
                for ( int i = 0 ; i < last ; i++)  
                {

                    if (time[i].name.equals("Any"))
                    {
                        return_string += "<b>[*] </b> Any" ;
                        return_string += "<br/>";

                    }
                    else
                    {
                        return_string += "<b>[T]</b> " + time[i].name;
                        return_string += "<br/>";
                    }


                }
            
                return_string += "</html> ";

                return return_string;
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVT) Error:" + e.getLocalizedMessage(), "781330", return_string);
                return "";
                
            }
        }
        
        public String prepare_cell_view_vpn(CheckPoint_Management_API_Rule_Processor.Object_vpn[] vpn)
        {
            String return_string = "";

            try
            {
            
                return_string += "<html> "; 



                int last = vpn.length;

                for ( int i = 0 ; i < last ; i++)  
                {

                    if (vpn[i].name.equals("Any"))
                    {
                        return_string +=  "<b>[*]</b> " + vpn[i].name;
                        return_string += "<br/>";
                    }
                    else
                    {

                        return_string +=  "<b>[V]</b> " + vpn[i].name;
                        return_string += "<br/>";

                    }

                }
            
                
                return_string += "</html> ";

                return return_string;
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVV) Error:" + e.getLocalizedMessage(), "221529", return_string);
                return "";
                
            }
            
        }        

       public String prepare_cell_view_track( CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule)
        {

            String return_string = "";

            try
            {

             return_string += "<html> "; 



            return_string += current_rule.track + " <br/> ";

            boolean temp = current_rule.track_per_session || current_rule.track_per_connection || current_rule.track_accounting || current_rule.track_firewall_session;

            if (temp)
            {
                return_string += "(";

            }

            if (current_rule.track_per_session)
            {

                return_string += "S";

            }
            if (current_rule.track_per_connection)
            {

                 return_string += "C";

            }
            if (current_rule.track_accounting)
            {
                return_string += "A";

            }
            if (current_rule.track_firewall_session)
            {
                return_string += "F";

            }

            if (temp)
            {
                return_string += ")";

            }

            if (!current_rule.track_alert.equals("none"))
            {
                return_string += " " + current_rule.track_alert;

            }
                                
            return_string += "</html> ";

            return return_string;
        }
         catch (Exception e)
        {

            log_handler.log_in_gui("(PCVT) Error:" + e.getLocalizedMessage(), "510887", return_string);
            return "";

        }
    }
        
        

        public String prepare_cell_view_service(CheckPoint_Management_API_Rule_Processor.Object_service[] service, boolean  service_negate)
        {
            String return_string = "";

            try
            {

                return_string += "<html> ";

                if (service_negate == true)
                {

                    return_string += "==== Negate ====  <br/>";

                }

           

                int last = service.length;

                for ( int i = 0 ; i < last ; i++)  
                {

                    if (service[i].type.equals("service-tcp"))
                    {

                     return_string +=   "<b>[T]</b> ";
                    }

                     if (service[i].type.equals("service-udp"))
                    {

                     return_string +=   "<b>[U]</b> ";

                    }

                    if (service[i].type.equals("service-icmp"))
                    {

                     return_string +=   "<b>[I]</b> ";

                    } 


                    if ((service[i].type.equals("service-group")) || (service[i].type.equals("application-site-group")))
                    {

                     return_string +=   "<b>[G]</b> ";

                    }


                    if ((service[i].type.equals("service-sctp")) || (service[i].type.equals("CpmiGtpMmV0Service")))
                    {

                     return_string +=   "<b>[Unsupported]</b> ";

                    }  



                    if (service[i].type.equals("service-other"))
                    {

                     return_string +=   "<b>[O]</b> ";

                    }

                    if (service[i].type.equals("service-rpc"))
                    {

                     return_string +=   "<b>[RPC]</b> ";

                    }

                    if (service[i].type.equals("service-dce-rpc"))
                    {

                     return_string +=   "<b>[DCE]</b> ";

                    }

                    if (service[i].type.equals("application-site"))
                    {

                     return_string +=   "<b>[A]</b> ";

                    }


                    if (service[i].type.equals("application-site-category"))
                    {

                     return_string +=   "<b>[C]</b> ";

                    }


                    if (service[i].type.equals("CpmiAnyObject"))
                    {

                     return_string +=   "<b>[*]</b> ";

                    } 

                    if (service[i].type.equals("data-center-object"))
                    {

                     return_string +=   "<b>[M]</b> ";

                    } 




                    return_string +=   service[i].name;

           


                    if (service[i].type == "service-dce-rpc")
                    {
                      //  return_string += " (SPECIAL)";

                    }
                    if (service[i].protocol != null)
                    {
                     //   return_string += " (" + service[i].protocol + ")";

                    }

                    if (service[i].cluster_sync == true)
                    {
                    //    return_string += " (SYNC)";

                    }

                    if (service[i].name == "Any")
                    {
                     //   return_string += " (SYNC)";

                    }



                     return_string += "<br/>";


                }

                if (service_negate == true)
                   {

                       return_string += "================<br/> ";

                   }

                return_string += "</html> ";

                return return_string;
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PCVS) Error:" + e.getLocalizedMessage(), "317375", return_string);
                return "";
                
            }
        }
        
        
}