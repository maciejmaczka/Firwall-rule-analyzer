/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package General;

import CheckPoint.CheckPoint_Management_API_Object_Processor;
import CheckPoint.CheckPoint_Management_API_Rule_Processor;
import CheckPoint.CheckPoint_Management_API_Rule_View;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
 


/**
 *
 * @author Maciej
 */

public class Config_File_Procesor 
{
   
    List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> rule_set;

    
    public  Log log_handler;

    public static void deleteFiles(File dirPath) {
      File filesList[] = dirPath.listFiles();
      for(File file : filesList) {
         if(file.isFile()) {
            file.delete();
          
            
         } else {
            deleteFiles(file);
         }
      }
   }
    
    public Set<CheckPoint_Management_API_Object_Processor.general_network_object>  json_objects_from_file(String directory)
    {
         
         try
         {
            Set<CheckPoint_Management_API_Object_Processor.general_network_object>  network_object_set;
            network_object_set =  new HashSet(); 
            
            FileInputStream fis_object =new FileInputStream(directory + "/network_obj.swa");       
            Scanner sc_object =new Scanner(fis_object);
            Gson gson = new Gson();
        
            String gno_string;            
            CheckPoint_Management_API_Object_Processor.general_network_object gno;
            while(sc_object.hasNextLine())  
            {
                
                gno_string = sc_object.nextLine();
                gno = gson.fromJson(gno_string,CheckPoint_Management_API_Object_Processor.general_network_object.class );
                network_object_set.add(gno);
                
            }
            
            sc_object.close();
            
            
            
         }
         catch (Exception e)
         {
             
              log_handler.log_in_gui("(JOFF) ERROR: " + e.getLocalizedMessage() , "178300" , "" );
              return null;
             
         }
         
        return null;
    }
    
    
    public List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> json_ruleset_from_file(String directory)
    {
        try
        {



            FileInputStream fis_ruleset =new FileInputStream(directory + "/ruleset.swa");       
            Scanner sc_ruleset=new Scanner(fis_ruleset);
            Gson gson = new Gson();
            
            String rule_string = "";
            CheckPoint_Management_API_Rule_Processor.Firewall_rule fw_rule;
            
            rule_set =  new ArrayList(); 
            
            while(sc_ruleset.hasNextLine())  
            {
                
                rule_string = sc_ruleset.nextLine();
                fw_rule = gson.fromJson(rule_string, CheckPoint_Management_API_Rule_Processor.Firewall_rule.class);
                rule_set.add(fw_rule);
                
            }
            
            sc_ruleset.close();
            
            return rule_set;
            
        }
        catch (Exception e)
        {
              
              log_handler.log_in_gui("(JRFF) ERROR: " + e.getLocalizedMessage() , "329164" , "" );
              return null;
            
        }
    }
    
    
    public void json_objects_to_file( Set<CheckPoint_Management_API_Object_Processor.general_network_object>  network_object_set,  String firewall_to_analyze)
    {
        
        try
        {
            File network_object_file = new File("DATA/" + firewall_to_analyze + "/network_obj.swa" );   
            
            FileWriter writer_object = new FileWriter(network_object_file.getPath());
            BufferedWriter bw_object = new BufferedWriter(writer_object) ;
            
            Iterator iter = network_object_set.iterator();
            
            Gson gson = new Gson();
            String jsonString;
            CheckPoint_Management_API_Object_Processor.general_network_object gno;
            
            
            while(iter.hasNext())
            {
                
                gno = (CheckPoint_Management_API_Object_Processor.general_network_object) iter.next();
                jsonString = gson.toJson(gno);
                
                bw_object.write(jsonString +"\n");
            }
            
            bw_object.close();
            
            
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui("(JOTF) ERROR: " + e.getLocalizedMessage() , "643994" , "" );
            
        }
        
        
    }
    
    
    public  void json_ruleset_to_file( List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> rule_set, String firewall_to_analyze)
    {
      // zapis regul zapory do plikow 
    
         try
        {
            
            
       //     CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
       //     CheckPoint_Management_API_Rule_Processor.Firewall_rule test_rule;
   
            File data_directory = new File("DATA");
            if (!data_directory.exists())
            {
                data_directory.mkdir();
                
            }
            
            File firewall_diectory = new File("DATA/" + firewall_to_analyze );
            if (!firewall_diectory.exists())
            {
                
                firewall_diectory.mkdir();
                
            }
            else
            {
                // dir exists 
                // remove old files 
                log_handler.log_in_gui(" Clearing old data.");
                deleteFiles(firewall_diectory);
                
                
            }
            
            
            File rule_file;
            File ruleset_file;
            
            Iterator rule_iterator = rule_set.iterator();
            CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule;
            
            
            ruleset_file = new File("DATA/" + firewall_to_analyze + "/ruleset.swa" );         
            FileWriter writer_rule_set = new FileWriter(ruleset_file.getPath());
            BufferedWriter bw_rule_set = new BufferedWriter(writer_rule_set) ;

                     
            while(rule_iterator.hasNext())
            {
               
               current_rule = (CheckPoint_Management_API_Rule_Processor.Firewall_rule) rule_iterator.next();
              
               rule_file = new File("DATA/" + firewall_to_analyze + "/R" + current_rule.number.toString() + "__" + current_rule.uid.toString() +".swa" );
               rule_file.createNewFile();
                
                Gson gson = new Gson();
                String jsonString = gson.toJson(current_rule);


                gson = new GsonBuilder().setPrettyPrinting().create();
                JsonParser jp = new JsonParser();
                JsonElement je = jp.parse(jsonString);
                String prettyJsonString = gson.toJson(je);


                bw_rule_set.write(jsonString +"\n");

                FileWriter writer_rule = new FileWriter(rule_file.getPath());
                BufferedWriter bw_rule = new BufferedWriter(writer_rule) ;

                bw_rule.write(prettyJsonString);

                bw_rule.close();

            
            }
            bw_rule_set.close();
             
            
            File file_fw_name = new File("DATA/" + firewall_to_analyze + "/firewall.swa" );
            FileWriter writer_fw_name = new FileWriter(file_fw_name.getPath());
            BufferedWriter bw_fw_name = new BufferedWriter(writer_fw_name) ;
            
            bw_fw_name.write(firewall_to_analyze);
            bw_fw_name.close();
            
            
            log_handler.log_in_gui(" Saved. \n");
              
        } 
       catch (Exception e)
        {

                log_handler.log_in_gui("(JRTF) ERROR: " + e.getLocalizedMessage() , "538229" , "" );

        }


     return;   
    }

}