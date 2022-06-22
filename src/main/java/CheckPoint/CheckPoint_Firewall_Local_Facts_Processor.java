/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint;

import CheckPoint.CheckPoint_Management_API_Object_Processor.ranges;
import CheckPoint.Windows.CheckPoint_Network_Object_Dictionary_Window;
import General.Log;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.StringTokenizer;

/**
 *
 * @author Maciej
 */
public class CheckPoint_Firewall_Local_Facts_Processor
{
    public Log log_handler;
    public CheckPoint_Management_API_Object_Processor Object_Processor_Handler;
    public CheckPoint_Network_Object_Dictionary_Window network_object_explorer;
    public CheckPoint_Management_API_Rule_Processor.Object_network_range dictionary_network_range_object;
    
    public String facts_directory = "";
    
    
     public Set<ranges> dynamic_object_ranges_local_facts;
     public Set<ranges> updatable_object_ranges_local_facts;
     public HashMap<String, Integer> identity_awareness_local_facts;
     
     public HashMap<String, String> country_codes;

     public Set<ranges> domain_objects_ranges_local_facts;
     
     public HashMap<String, String> application_match_overide;
     
    public void start_processing()
    {
        log_handler.log_in_gui("Reading local configuration: \n" , "" , "");
        read_dynamic_objects();
              
        read_updatable_objects();
        
        read_idenitiy_awareness();
        
        read_domains_objects();
        
        read_application_match_settings();
        
        read_service_group();
        
        log_handler.log_in_gui("Reading local configuration: Completed\n" , "" , "");
        
    }

    public void read_service_group()
    {
         String error_line = "";
             try
        {
            
            application_match_overide = Object_Processor_Handler.application_match_overide;
            
            Path path = Paths.get(facts_directory + "\\service_group.swa");
            List < String > input = Files.readAllLines(path);
            
            Iterator iter = input.iterator(); 
                        
            while (iter.hasNext()) 
            {
                String app_id = "";
                String service ="";
                
                String  line = (String) iter.next();
                
                if (line.contains(":name (WEB_BROWSING_SERVICES_GROUP_"))
                {
                    
                    app_id = line.replace(":name (WEB_BROWSING_SERVICES_GROUP_", "");
                   
                    app_id = app_id.replace("(", "");
                    app_id = app_id.replace(")", "");
                    app_id = app_id.replaceAll(" ", "");
                    app_id = app_id.replaceAll("\t", ""); 
                    
                    
                   // System.out.println(" > " + app_id);
                    
                    Object_Processor_Handler.web_services_group_uid = app_id;
                    
                    
                     while (iter.hasNext()) 
                     {
                         
                         line = (String) iter.next();
                         
                         if (line.contains("members"))
                         {
                             line = (String) iter.next();
                             while(line.replaceAll("\t", "").startsWith(":") )
                             {

                                 line = line.replace("(", "");
                                 line = line.replace(")", "");
                                 line = line.replace(":", "");
                                 line = line.replaceAll(" ", "");
                                 line = line.replaceAll("\t", ""); 
                                 
                                 service += line + ";";
                                 
                                 
                                 
                                 line = (String) iter.next();
                                 
                             }
                             
                             break;
                             
                         }
                         
                         
                     }
                     
                     Object_Processor_Handler.application_match_overide.put(app_id, service + ";" + "false");
                    // System.out.println(app_id + " " + service + ";" + "false");
                    
                }
                
            }
            
            
            
            log_handler.log_in_gui("Web Service Groups: OK \n" , "", ""); 
        }
        catch (Exception e)
        {
            
                 log_handler.log_in_gui("(LF RSG) Error: " + e.getMessage(), "978125", error_line);
            
        }
    }        
    

    public void read_application_match_settings()
    {
        
        String error_line = "";
        
        try
        {
            
            application_match_overide = Object_Processor_Handler.application_match_overide;
            
            Path path = Paths.get(facts_directory + "\\application_match_settings.swa");
            List < String > input = Files.readAllLines(path);
            
            Iterator iter = input.iterator();
            String negate = "false";
            
          
            while (iter.hasNext()) 
            {
                String app_id = "";
                String service ="";
                
                
                String  line = (String) iter.next();
                error_line = line; 
               
                if (line.contains(":negate (true)"))
                {
                 
                    negate = "true";
                    
                }
                
                if (line.contains(":negate (false)"))
                {
                    
                    negate = "false";
                    
                }
                
                
                 if (line.contains(":orig_uuid"))
                 {
                     
                     
                     app_id = line.replace("orig_uuid", "");
                     app_id = app_id.replace("(", "");
                     app_id = app_id.replace(")", "");
                     app_id = app_id.replace(":", "");
                     app_id = app_id.replaceAll(" ", "");
                     app_id = app_id.replaceAll("\t", ""); 
                     // found oryginal uid (appliacation id)
                       
                     // System.out.println(" + " + app_id);
                     
                  
                      while(!line.contains("AdminInfo"))
                      {
                          
                          line = (String) iter.next();  
                          if (line.contains(":services ()"))
                          {
                              
                              // no services, any
                              service = "Any;";
                         
                              break;        
                              
                              
                              
                          }
                        
                          if (line.contains(":services ("))
                          {
                              line = (String) iter.next();
                              // customizowana aplikacja 
                              while(!line.contains(":AdminInfo"))
                              {
                               
                                 String tmp = "";
                                 
                                 tmp = line.replace("(", "");
                                 tmp = tmp.replace(")", "");
                                 tmp = tmp.replace(":", "");
                                 tmp = tmp.replaceAll(" ", "");
                                 tmp = tmp.replaceAll("\t", ""); 
                                
                                 if (tmp.length() != 0)
                                 {
                                    service += tmp + ";";
                               
                                     
                                 }
                                 
                                
                                  
                                  if (iter.hasNext())
                                  {
                                    line = (String) iter.next();
                                  }
                                  else
                                  {
                                    line = ":AdminInfo";
                                      
                                  }
                              
                              }
                              
                              
                          }
                          
                          
                        
                          // else next line
                          
                          
                          
                      }
         
               //       System.out.println("|" + app_id  + "| " + service + ";" + negate );
                      Object_Processor_Handler.application_match_overide.put(app_id, service + ";" + negate);
                    
               //     System.out.print(">>>>>>>>>>>> " + Object_Processor_Handler.application_match_overide.size() + "       \n");
                    
                    
               
                     
                 }
                 else
                 {
                     
                 }
                 
                
            }
            
            
               log_handler.log_in_gui("Application Match: " + Object_Processor_Handler.application_match_overide.size() + " Objects \n"  , "", ""); 
            
            
        }
        catch (Exception e)
        {
            
             
            log_handler.log_in_gui("(LF RAMS) Error: " + e.getMessage(), "848044", error_line);
            
        }
        
        
    }
    
    
    public void read_country_codes()
    {
        String error_line = "";
        
        try
        {
            country_codes = new HashMap<>();
        
            Path path = Paths.get("country_code.swa");
            String input = Files.readAllLines(path).toString();
            StringTokenizer st = new StringTokenizer(input ,",");
             
            while (st.hasMoreTokens()) 
            {
                String line = st.nextToken();
                 error_line = line;
                String country_name;
                String country_code;
               
                try
                {
                    StringTokenizer country_token = new StringTokenizer(line ,";");

                    country_name = country_token.nextToken();
                    
                    
             
                    
                    if (country_name.startsWith(" "))
                    {
                         country_name = country_name.replaceFirst( " ", "");
                        
                    }
                    country_code = country_token.nextToken();
                    
                    if (country_code.startsWith(" "))
                    {
                        country_code = country_code.replaceFirst(" ", "");
                    }
                    
                    
                    
                 
                   
                //   System.out.println( "|" + country_code + "|" + country_name + "| " +country_codes.size());
                                                
                             
               
                    
                    country_codes.put(country_code, country_name);
                    
                    // kraj znaleziony w pliku
                    
                    {
                        
                        
                        
                        
                        
                    }
                    
                    
                    
                    
                }
                catch (Exception e)
                {
                    
                    log_handler.log_in_gui("(LF RCC) Error: " + e.getMessage(), "638745", error_line);
                    
                }
                
                
                
           
            }
            
  
            
        
        }
        catch (Exception e)
        {
            
                        
            log_handler.log_in_gui("(LF RCC) Error: " + e.getMessage(), "716402",  "" );
            
            
        }
         
        
    }
  
    public void read_domains_objects()
    {
        String error_line = "";
        
        try
        {
        
            CheckPoint_Management_API_Object_Processor temp = new CheckPoint_Management_API_Object_Processor();
            ranges domain_range;
                        
            
            domain_objects_ranges_local_facts = Object_Processor_Handler.domain_objects_ranges_local_facts;
            Path path = Paths.get(facts_directory + "\\domain_objects.swa");
            List < String > input = Files.readAllLines(path);
             
            Iterator iter = input.iterator();
            
            String local_cfg = "";
            
            while (iter.hasNext()) 
            {
                local_cfg = "";
                String  line = (String) iter.next();
                error_line = line; 
                 
                 
                 if (line.startsWith("#START#"))
                 {
                  
                     line = (String) iter.next();  // " ----------------------------------------"
                     local_cfg += line; 
                     
                     line = (String) iter.next();   // | Given Domain name:  clico.pl  FQDN: yes                                                         |
                     local_cfg += line; 
                     
                     
                     if (line.contains("Given Domain name"))
                     {
                         line = line.replaceAll("Given Domain name:", "");
                         line = line.replaceAll("FQDN: no", "");
                         line = line.replaceAll("FQDN: yes", "");
                         line = line.substring(1, line.length() - 1);
                         line = line.replaceAll(" ", "");
                         
                         String domain = line;
                         
                       //  System.out.println(domain);
                         
                         line = (String) iter.next();  // " ----------------------------------------"
                         local_cfg += line; 
                         
                         
                        line = (String) iter.next();  // | IP address                                                                         | sub-domain |
                        local_cfg += line; 
                     
                     
                        line = (String) iter.next();  // " ----------------------------------------"
                        local_cfg += line; 
                        
                        
                        while (!line.equals("#END#"))
                        {
                            line = (String) iter.next();
                           
                            if (line.startsWith("#END#"))
                            {
                                
                                break;
                                
                            }
                            
                            local_cfg += line;
                            
                            
                            
                            if ((line.startsWith("Total of")) || (line.startsWith("-------------")) || (line.length() < 1))
                            {
                               
                            }
                            else
                            {
                                
                               
                                line = line.substring(1, line.length() - 15);
                                line = line.replaceAll(" ", "");
                                String ip_address = line;
                         //       System.out.println(line);
                                
                                domain_range = temp.new ranges();
                                domain_range.name = domain;
                                domain_range.range_start = ip_address;
                                domain_range.range_end = ip_address;
                                domain_range.local_config = domain_range.name + " "  + domain_range.range_start + "\n" ;
                                
                            
                                domain_objects_ranges_local_facts.add(domain_range);
                            }
                            
                            
                        }
                     }
                     
                                       

                 }
                 
                 
            } 
                 
             //    if ( line.contains("Given IP address:"))
             //    {
                     
                    // String local_cfg_ip = line;
                     
                    // line = line.replaceAll(" ", "");
                    // line = line.replaceAll("GivenIPaddress:", "");
                    // line = line.substring(1, line.length() - 1);
                    // System.out.println("> " + line);
                     
                     //String ip_address = line;
                     
                     //iter.next(); // for ---------------------
                     //iter.next(); // for header
                     //iter.next(); // for --------------------
                    
                     
                    // line = (String) iter.next();   // for domain value
                    //  while (!line.startsWith("--------")) 
                    //  {
                          
                          
                     //      String local_cfg_domain = line;
                      //     line = line.substring(2, line.length() - 10);
                     //      line = line.replaceAll(" ", "");
                           
                     //      String domain_name = line;
                           
                          // System.out.println(line);
                      //     domain_range = temp.new ranges();
                      //     domain_range.name = domain_name;
                      //     domain_range.range_start = ip_address;
                      //     domain_range.range_end = ip_address;
                       //    domain_range.local_config = local_cfg_domain + "\n" + local_cfg_ip;
                           //domain_range.local_config 
                            
                       //    domain_objects_ranges_local_facts.add(domain_range);
                           
                           
                           
                       //   line = (String) iter.next();

                          
                   //   }
                     
                 //}
                 
           // }
            
            

                
              //  Iterator it = domain_objects_ranges_local_facts.iterator();
                
               // while(it.hasNext())
             //   {
                 //   ranges dd = (ranges) it.next();
                   // System.out.println(dd.name + " "  + dd.range_start + " " +dd.range_end );
                  //  System.out.println(dd.local_config);
                    
              //  }
            
            log_handler.log_in_gui("Domain Objects: " + domain_objects_ranges_local_facts.size() + " Ranges \n"  , "", ""); 
           
        }
        catch (Exception e)
        {
                    
            log_handler.log_in_gui("(LF RDO) Error: " + e.getMessage() + " " + error_line, "810977" , error_line);
               
            
        }
                
        
        
    }
    
    
        
    public void read_idenitiy_awareness()
    {
        String error_line = "";
        
        
        try
        {
             identity_awareness_local_facts = Object_Processor_Handler.identity_awareness_local_facts;
             Path path = Paths.get(facts_directory + "\\identity_awareness.swa");
             List < String > input = Files.readAllLines(path);
             
             
             Iterator iter = input.iterator();
            
             while (iter.hasNext()) 
               {
                 String  line = (String) iter.next();
                 //  System.out.println(line);
                 error_line = line;
                 
                 if((line.replaceAll(" ", "").startsWith("Groups:")) || (line.replaceAll(" ", "").startsWith("Roles:")))  
                 {
                     
                     line = line.replaceFirst("   Roles: ", "");
                     line = line.replaceFirst("   Groups: ", "");
                     
                      
                        StringTokenizer st = new StringTokenizer(line ,";");

                        while (st.hasMoreTokens()) 
                        {
                            String group_name = st.nextToken();
                          

                            Object tmp = identity_awareness_local_facts.get(group_name);
                            
                            if (tmp == null)
                            {
                                
                                //System.out.println(group_name + " not found " );
                                identity_awareness_local_facts.put(group_name, 1);
                                
                            }
                            else
                            {
                                
                                int group_count = (Integer) tmp;
                                group_count++;
                                
                                identity_awareness_local_facts.replace(group_name, group_count);
                           //     System.out.println(group_name + " updatet count  " + group_count );
                                
                                
                            }
                            
                         
                            
                        }
                 
                     
                   
                     
                 }
                 
               //  if (line.replaceAll(" ", "").startsWith("Client Type:"))
                {

                    //System.out.println("> " + line);
                    
                }
                 
               }
                
             
             log_handler.log_in_gui("Identity Awareness: " + identity_awareness_local_facts.size() + " Groups (Users, DC, IoT)\n" , "", ""); 
             
             
        }
        catch (Exception e)
        {
            
           
            log_handler.log_in_gui("(LF RIA) Error: " + e.getMessage() + " " + error_line, "682231" , error_line);
            
        }
        
    }
    
    public void read_updatable_objects()
    {
        
        String error_line = "";
        String line = "";
        
        try 
        {
            
            read_country_codes();
            
            updatable_object_ranges_local_facts = Object_Processor_Handler.updatable_object_ranges_local_facts;
            
             Path path = Paths.get(facts_directory + "\\updatable_objects.swa");
             String input = Files.readAllLines(path).toString();
            
             StringTokenizer st = new StringTokenizer(input ,",");
            
            while (st.hasMoreTokens()) 
            {
                line = st.nextToken();
                error_line = line;
                
                if (line.startsWith("object name") || line.startsWith(" object name"))
                {
               
                    
                    
                    if (line.startsWith("object name : CP_") || line.startsWith(" object name : CP_"))
                    {
                        CheckPoint_Management_API_Object_Processor temp = new CheckPoint_Management_API_Object_Processor();
                        ranges updatable_range;
                        
                        String count_code = "";                 
                        
                        if (line.indexOf("CP_GEO") > 0)
                        {
                        
                             count_code = line.replaceAll( "object name : CP_GEO_", "");
                             count_code = count_code.replaceAll( " ", "");
  
                             
                  
                        }
                        else 
                        {
                            count_code = line.replaceAll( "object name : ", "");
                            count_code = count_code.replaceAll( " ", "");
                        }
                        
                        
                        String name = (String) country_codes.get(count_code);
                        if (name == null)
                        {
                            log_handler.log_in_gui("(Warning) Object not found |" + count_code + "| " +  error_line + "\n");
                            name = "UNKNOWN";
                            
                        }
                        
                        String local_config;
                         int number = 0;
                         line = st.nextToken();
                       //  System.out.println(name);
                         
                        while ((line.startsWith("range") || line.startsWith(" range")))
                        {
                            
                            updatable_range = temp.new ranges();
                            
                         
                            
                            if (name.startsWith(" ") )
                            {
                            
                                updatable_range.name = name.replaceFirst(" ", "")  ;
                            
                            }
                            else
                            {
                                
                                updatable_range.name = name;
                                
                            }
                  
                            
                            updatable_range.number = Integer.toString(number);
                            local_config = line + "\n";
                            // czytamy obiekty i rozdzielamy ip

                            StringTokenizer range_tkn = new StringTokenizer(line ,":");

                            
                            String firstPart = line.substring(0, line.indexOf(":"));
                            String range_tmp = line.substring(line.indexOf(":")+1);
                            
                            range_tkn.nextToken();
                            //String range_tmp = range_tkn.nextToken();

                           

                            {

                                StringTokenizer range_tkn2 = new StringTokenizer(range_tmp ," ");
                                String start_ip = range_tkn2.nextToken();
                                String end_ip = range_tkn2.nextToken();


                                updatable_range.range_start =  start_ip;
                                updatable_range.range_end = end_ip;


                            }
                            
                            if ((validate_ipv4(updatable_range.range_start)) && (validate_ipv4(updatable_range.range_end)))
                            {
                                
                                updatable_range.local_config = local_config;
                                updatable_object_ranges_local_facts.add(updatable_range);
                                
                            }
                            line = st.nextToken();
                            number++;
                     
                        }
                        
                        
                    }
                    
                
                }
            }
            
           
       //   Iterator i = updatable_object_ranges_local_facts.iterator();
        //      File file = new File ("output.swa");
       //     BufferedWriter out = new BufferedWriter(new FileWriter(file)); 


         //   while (i.hasNext())
         //   {
        //      ranges rng = (ranges) i.next();
              
        //      out.write(">" + rng.name + "<\n");
        //      out.write(rng.range_start + " " + rng.range_end + "\n");
           //   out.write(rng.local_config);
              
                
        //    }
        //       out.close();
            
           
        
        
            log_handler.log_in_gui("Updatable Objects: " + updatable_object_ranges_local_facts.size() + " Ranges\n" , "" , ""); 
        }
        catch (Exception e)
        {
            
            log_handler.log_in_gui("(LF RUO) Error: " + e.getMessage() + " " + error_line, "614239", error_line);
            
        }
                
        
        
        
    }
    
    public static boolean validate_ipv4(final String ip)
    {
    String PATTERN = "^((0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)\\.){3}(0|1\\d?\\d?|2[0-4]?\\d?|25[0-5]?|[3-9]\\d?)$";

    return ip.matches(PATTERN);
    }
    
    
    public void read_dynamic_objects()
    {
       String error_line = "";
      
       try
       {
            dynamic_object_ranges_local_facts = Object_Processor_Handler.dynamic_object_ranges_local_facts;
         
          
            Path path = Paths.get(facts_directory + "\\dynamic_objects.swa");
            String input = Files.readAllLines(path).toString();
            
            StringTokenizer st = new StringTokenizer(input ,",");
           
            
            while (st.hasMoreTokens()) {
                
                String line = st.nextToken();
                error_line = line;
                String object_name = "";

                String local_config = "";
                

                
                
                if (line.startsWith("object name") || line.startsWith(" object name"))
                {
                    
                    CheckPoint_Management_API_Object_Processor temp = new CheckPoint_Management_API_Object_Processor();
                    ranges local_range;
                    
                    
                    // znalazlem nowy obiekt
                    
                    
                    local_config += line + "\n";
                    line = line.replaceFirst("object name : ", "").replaceAll(" ", "");                   
                    String name = line;
                  

                    
                    line = st.nextToken();
                    int number = 0;
                    
                    while ((line.startsWith("range") || line.startsWith(" range")))
                    {
                        local_range = temp.new ranges();
                        local_range.name = name  ;
                        local_range.number = Integer.toString(number);
                        local_config = line + "\n";
                        // czytamy obiekty i rozdzielamy ip
                       
                        StringTokenizer range_tkn = new StringTokenizer(line ,":");

                        String firstPart = line.substring(0, line.indexOf(":"));
                        String range_tmp = line.substring(line.indexOf(":")+1);
                        
                      //  range_tkn.nextToken();
                       // String range_tmp = range_tkn.nextToken();
                        
                        
                        
                        {

                            StringTokenizer range_tkn2 = new StringTokenizer(range_tmp ," ");
                            String start_ip = range_tkn2.nextToken();
                            String end_ip = range_tkn2.nextToken();
                         
   
                            local_range.range_start =  start_ip;
                            local_range.range_end = end_ip;
                           
                            
                        }
                        local_range.local_config = local_config;
                        dynamic_object_ranges_local_facts.add(local_range);
                        
                        
                        
                        line = st.nextToken();
                        number++;
                        
                    }
                    

                
                 
                 
                 
                }
                
                
     
            }
            
            
            log_handler.log_in_gui("Local Dynamic Objects: " + dynamic_object_ranges_local_facts.size() + " Ranges\n" , "" , "");
            
            /*
            Iterator i = dynamic_object_ranges_local_facts.iterator();
            
            while (i.hasNext())
            {
              ranges rng = (ranges) i.next();
              
              System.out.println(rng.name);
              System.out.println(rng.range_start + " " + rng.range_end);
              System.out.println(rng.local_config);
              
                
            }
            */
            
       } 
       catch (Exception e)
       {
           log_handler.log_in_gui("(LF RDO) Error: " + e.getMessage(), "72690", error_line);
       
       }
        
        
    }
    
    
    
}
