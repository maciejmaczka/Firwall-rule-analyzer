/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint;
import CheckPoint.CheckPoint_Management_API_Rule_Processor.Firewall_rule;
import General.Log;
import com.google.gson.Gson;
import java.io.BufferedWriter;
import java.io.FileWriter;


import org.json.simple.JSONObject; 
import org.json.simple.parser.*; 
import org.apache.http.*;
import org.apache.http.client.methods.HttpPost;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.Set;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
/**
 *
 * @author Maciej
 */



public class CheckPoint_Management_API 
{

    public Log log_handler;                 // obsluga logowania
    JTable GUI_Ruleset_Table;               // widok rulesetu w gui
    Map<String, Integer > table_columns ;   // kolumny

    boolean Mgmt_API_Server_Loged_In = false;

        
    String Mgmt_API_Server_IP = "192.168.10.100";   // logowania
    String Mgmt_API_Server_Port = "443";
    String Mgmt_API_Server_User = "admin";
    String Mgmt_API_Server_Password = "vpn123";
    String User_Agent = "Black-Wall-SI";
    
                                                    // uwierztelnie
    boolean Mgmt_API_Server_Ignore_Cert = true;        
    String Mgmt_API_Server_Auth_Token  = "";


    HttpClient API_Client;       
    HttpHost MGMT_Server;

    public CheckPoint_Management_API_Object_Processor Object_Processor_Handler;
    public CheckPoint_Management_API_Rule_Processor Policy_Processor_Handler;

    String FIREWALL_to_analyze = "";

    // tempy

    String last_section_uid = "";
    
    
    
    // rule set
    List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> rule_set;


         
    public void merge_rule_table(JTable GUI_Ruleset_Table,  Map<String, Integer > table_columns)
    {
        
        this.table_columns = table_columns;
        this.GUI_Ruleset_Table = GUI_Ruleset_Table;
        
        
    }
        

    
    public void show_network_object_dictionary()
    {
        
         if (Object_Processor_Handler == null)
         {
             
             log_handler.log_in_gui("Objects not loaded. Please use Connect -> Management API", "78522" , "");
             
         }
         else
         {
             Object_Processor_Handler.show_network_object_dictionary();
         }
        
       
        
    }

    public boolean API_SID_Return()
    {
        
        if ((Mgmt_API_Server_Auth_Token.equals("")) || (Mgmt_API_Server_Auth_Token == null))
        {
            
            return false;
        }
        
        return true;
    }
    
    
    
    public void set_connection_paramters(String Management_IP, String Management_Port, String Username, char[] Password, boolean Igore_Cert)
    {
        
        Mgmt_API_Server_IP = Management_IP;
        Mgmt_API_Server_Port = Management_Port;
        Mgmt_API_Server_User = Username;
        Mgmt_API_Server_Password  = new String(Password);
        Mgmt_API_Server_Ignore_Cert = Igore_Cert;
        
        
    }
    
    
    public String Mgmt_API_body_parser_show_layer(String responseString)
        {
            //
            //
            //   read information about layer
            //
            //
            
            
            
            try
            {
                        
                Object rss_parser = new JSONParser().parse(responseString);     
                JSONObject rss = (JSONObject) rss_parser; 

         
                String type = (String)rss.get("type");
                String app_url = (String)rss.get("applications-and-url-filtering");
                String con_awar = (String)rss.get("content-awareness");
                String mobile = (String)rss.get("mobile-access");
                String firewall = (String)rss.get("mobile-access");
                String implicit_deny = (String)rss.get("implicit-cleanup-action");

            } 
            catch (Exception e)
            {
               
                log_handler.log_in_gui("(MABPSL) ERROR: " + e.getLocalizedMessage() , "94861" , responseString );
              
                
            }
                
                    
            
            
            return responseString;

        }
    
        public boolean API_Still_Connected()
        {
            
            try
            {
                
                String response_body_human = Mgmt_API_REST_Call("show-sessions", " { } ");
                
                Object rss_parser = new JSONParser().parse(response_body_human);     
                JSONObject rss = (JSONObject) rss_parser; 


                String state = (String)rss.get("code");
                
                if (state == null)
                {
                    // nie znalazlem kodu bledu w sensie jestem polaczony
                    return true;
                    
                }
                
                
              
                return false;
                
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("We don't have valid session. Reconnecting. " + e.getLocalizedMessage(), "55506" , "");
               
                return false;
                
            }
            
    
            
            
          
        }
    
    
       // zaloguj
        public void API_Login()
        {

            String response_string = "";

            try
            {         
                
                // just message
                
                log_handler.log_in_gui("Connecting to https://" + Mgmt_API_Server_IP + ":" + Mgmt_API_Server_Port + "\n", "" , "");
                log_handler.refresh_log_area();

                 
                
                //
                // ignore certyficates 
                //
                
                if (Mgmt_API_Server_Ignore_Cert)
                {
                    TrustManager[] trustAllCerts = new TrustManager[] { 
                        new X509TrustManager() {     
                            public java.security.cert.X509Certificate[] getAcceptedIssuers() { 
                                return new X509Certificate[0];
                            } 
                            public void checkClientTrusted( 
                                java.security.cert.X509Certificate[] certs, String authType) {
                                } 
                            public void checkServerTrusted( 
                                java.security.cert.X509Certificate[] certs, String authType) {
                            }
                        } 
                    }; 
                 
                    SSLContext sc = SSLContext.getInstance("SSL"); 
                    sc.init(null, trustAllCerts, new java.security.SecureRandom()); 
                    HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());


                    // API CLIENT for untruset certs
                    
                    API_Client = HttpClientBuilder.create().setSSLContext(sc).build();
                    
                }
                else
                {
                    // API CLIENT for trusted certs
                    
                    API_Client = HttpClientBuilder.create().build();
                    
                }
                 


                //
                // Login header and body
                //

                
                HttpHost API_Server = new HttpHost(Mgmt_API_Server_IP,  Integer.parseInt(Mgmt_API_Server_Port), "https");    
                HttpPost API_Post_Call = new HttpPost("/web_api/login");
                API_Post_Call.addHeader("Content-Type", "application/json");
                API_Post_Call.addHeader("User-Agent", User_Agent);
                
               
                Map<String,String> API_Body = new HashMap<String,String>();
                API_Body.put("user", Mgmt_API_Server_User);
                API_Body.put("password", Mgmt_API_Server_Password);
                API_Body.put("read-only", "true");            
                API_Body.put("session-timeout", "3600");

                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();
                
            
                
                StringEntity Post_Body = new StringEntity(body_string);
                API_Post_Call.setEntity(Post_Body); 
               
             
               //
               // execute query
               //
               
               HttpResponse API_Response = API_Client.execute(API_Server, API_Post_Call);               
               response_string = EntityUtils.toString(API_Response.getEntity());
                     
         
                //
                // Get the response
                //
                
                boolean logon_success = Mgmt_API_Connection_Login_Parser(response_string);
                if (logon_success == true)
                {
                    
                    log_handler.log_in_gui("Authentication succeeded \n" , "" , "");

                }
                else
                {

                    log_handler.log_in_gui("Authentication failed. Invalid username or password. \n","" , "");

                }

            }

            catch (Exception e)
            {

                //
                // Something went wrong
                // Multi exception handler
                //
                if (response_string == null)
                {
                    response_string = "Empty response. ";
                }

                log_handler.log_in_gui("Connection failed: " + e.getLocalizedMessage() + "\n", "" , response_string );
                
                
                return;
            }

        }



    
    
     private boolean Mgmt_API_Connection_Login_Parser(String responseString)
        {

            //
            //
            // GET SID TOKEN
            //
            //
            
           
            
           try
           {

            
                Object rss_parser = new JSONParser().parse(responseString);     
                JSONObject rss = (JSONObject) rss_parser; 

        
            
                Mgmt_API_Server_Auth_Token = (String)rss.get("sid");

                if ((rss_parser == null ) )
                {

                    
                  
                     return false;
                }
                
                if  (Mgmt_API_Server_Auth_Token == null)
                {

                   
                    return false;
                }

             
                
                return true;
                
           }
        
           catch (Exception e)
           {
               
                 log_handler.log_in_gui("Host is alive, but there is something wrong with communication. \n" , "" , responseString );
               
                 return false;
           }

            
        }


        public String Mgmt_API_body_builder_show_rule_set_human_view(String name, int offset)
        {

            //
            //
            //  show rulebase  normal view  - object names
            //  20 rules by query
            //
            // name - layer name
            // offset *  20 rules

            try
            {
            
                offset = offset * 20;

                HashMap<String,Object> API_Body = new HashMap<String,Object>();
                API_Body.put("name", name);
                API_Body.put("offset", String.valueOf(offset));
                API_Body.put("show-hits", "true");
                API_Body.put("use-object-dictionary", "false");
                API_Body.put("limit", "20");
                API_Body.put("show-as-ranges", "false");
              
                API_Body.put("details-level", "standard");  
             
                
                HashMap<String,Object> hits_setting_map = new HashMap<String,Object>();
                hits_setting_map.put("target", FIREWALL_to_analyze);
                API_Body.put("hits-settings", hits_setting_map);

                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;

           }
            catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSRSHV) Error: \n" + e.getLocalizedMessage(), "507710" , name + " " +  offset );
               
                return null;
           }

        }

        public String Mgmt_API_body_builder_show_layers()
        {

            //
            //
            //  show all layers
            //  
            //
            // no offset
            // limit 500
            //
            
            try
            {
                   

                String limit = "500";

                Map<String,String> API_Body = new HashMap<String,String>();
                API_Body.put("limit", limit);


                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;

            
            }
            catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSL) Error: \n" + e.getLocalizedMessage(), "187117" , "" );
               
                return null;
           }
            
        }
    
          public String Mmgt_API_body_builder_empty_body()
        {
            
            return "{ } ";
        }
        

        
        public String Mgmt_API_body_builder_show_layer(String name)
        {

            //
            //
            //  show rulebase  layer info
            //  
            //

           
            try
            {

                Map<String,String> API_Body = new HashMap<String,String>();
                API_Body.put("name", name);


                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;
                
            }
           catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSL) Error: \n" + e.getLocalizedMessage(), "958191" , "" );
               
                return null;
           }
            
            

        }
        
        
          // standardowe wyslanie zapytania
        public String Mgmt_API_REST_Call(String function, String body_string)
        {

            //
            //
            //  standard REST API CALL
            //  Used everywhere
            //



            // sprawdzic czy polaczenie jeszcze jest wazne 

            try
            {

                //
                // HEADER 
                //

                        
                HttpHost API_Server = new HttpHost(Mgmt_API_Server_IP,  Integer.parseInt(Mgmt_API_Server_Port), "https");    
                HttpPost API_Post_Call = new HttpPost("/web_api/" + function);
                API_Post_Call.addHeader("Content-Type", "application/json");
                API_Post_Call.addHeader("X-chkp-sid", Mgmt_API_Server_Auth_Token);
                API_Post_Call.addHeader("User-Agent", User_Agent);
                
                
                StringEntity Post_Body = new StringEntity(body_string);    
                API_Post_Call.setEntity(Post_Body); 
               
             
               //
               // execute query
               //
               
               HttpResponse API_Response = API_Client.execute(API_Server, API_Post_Call);
               
               String response_string = EntityUtils.toString(API_Response.getEntity());
               

               return response_string;
               
               

            }
            catch (Exception e)
            {

                log_handler.log_in_gui("ERROR:"  + function + "\n", "78801" , function + " " + body_string);
                return null;
                
                
            }


        }


        public  List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> get_ruleset()
        {
            
            
            return rule_set;
        }
        
        public void Mgmt_File_Process_Ruleset(List<CheckPoint_Management_API_Rule_Processor.Firewall_rule> rule_set, String firewall_name)
        {
            try
            {
                
                DefaultTableModel remove_table_model = (DefaultTableModel) GUI_Ruleset_Table.getModel();
                remove_table_model.setRowCount(0);
                //rule_set =  new ArrayList();
         
                
                
                CheckPoint_Management_API_Rule_Processor rule_processor_handler = new CheckPoint_Management_API_Rule_Processor();
                rule_processor_handler.log_handler = log_handler;

                CheckPoint_Management_API_Rule_View api_rule_view_processor = new CheckPoint_Management_API_Rule_View();

                api_rule_view_processor.merge_jtable(GUI_Ruleset_Table, table_columns);
                api_rule_view_processor.log_handler = log_handler;            

                CheckPoint_Management_API_Rule_Processor tmp_rule_procesor = new CheckPoint_Management_API_Rule_Processor();
                CheckPoint_Management_API_Rule_Processor.Firewall_rule current_firewall_rule;

                Iterator iter = rule_set.iterator();
                
                while(iter.hasNext())
                {
                    
                   CheckPoint_Management_API_Rule_Processor.Firewall_rule current_rule = (CheckPoint_Management_API_Rule_Processor.Firewall_rule) iter.next();
                  
                   
                   if(current_rule.type.equals("access-rule"))
                   {
                        api_rule_view_processor.prepare_rule_view(current_rule ,false);  
                        continue;
                   }
                   
                   
                   if(current_rule.type.equals("access-section"))
                   {
                        api_rule_view_processor.prepare_section_view(current_rule);
                   }
                }
                
               

            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(MFPR) Error: \n" + e.getLocalizedMessage(), "214712" , "" );
                
                
                
            }
            
            
            
        }
       
            public String Mgmt_API_body_builder_show_generic_object(String uid)
        {

            //
            //
            //  show rulebase  normal view  - object names
            //  20 rules by query
            //
            // name - layer name
            // offset *  20 rules

            try
            {
            
              

                HashMap<String,Object> API_Body = new HashMap<String,Object>();
              
               
                API_Body.put("uid", uid);           
                
             
                
                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;

           }
            catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSAS) Error: \n" + e.getLocalizedMessage(), "507710" ,  "" );
               
                return null;
           }

        }
       
         
        public String Mgmt_API_body_builder_show_categories()
        {

            //
            //
            //  show all categories
            //
            //

            try
            {
            
              
                HashMap<String,Object> API_Body = new HashMap<String,Object>();
              
               
                API_Body.put("limit", "500");           
                API_Body.put("details-level", "standard");  
             
                
                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;
                

           }
            catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSAS) Error: \n" + e.getLocalizedMessage(), "507710" ,  "" );
               
                return null;
           }

        }
            
            
        
        public String Mgmt_API_body_builder_show_applications(int offset)
        {

            //
            //
            //  show rulebase  normal view  - object names
            //  20 rules by query
            //
            // name - layer name
            // offset *  20 rules

            try
            {
            
                offset = offset * 100;

                HashMap<String,Object> API_Body = new HashMap<String,Object>();
              
                API_Body.put("offset", String.valueOf(offset));
                API_Body.put("limit", "100");           
                API_Body.put("details-level", "full");  
             
                
                JSONObject API_Body_json = new JSONObject(API_Body);
                String body_string = API_Body_json.toJSONString();

                return body_string;

           }
            catch (Exception e)
           {
               
                log_handler.log_in_gui("(MABBSAS) Error: \n" + e.getLocalizedMessage(), "507710" ,  "" );
               
                return null;
           }

        }
        
        public void Mgmt_API_Build_App_Database()
        {
            
            log_handler.log_in_gui(" Building APP Database. Please wait. \n");
     
            
            
            
            try
            {
                
                HashMap<String, ArrayList<String>> categories = new HashMap<String, ArrayList<String>>();
                ArrayList<String> applications_in = new ArrayList<>();
                
                int count = 0;
                                    // 200
                for (int i = 0 ; i < 200 ; i++)
                {
                    
                    String reguest_body_app = Mgmt_API_body_builder_show_applications(i);
                    String response_body_app = Mgmt_API_REST_Call("show-application-sites", reguest_body_app);
                    
                    Object rss_parser_app = new JSONParser().parse(response_body_app);     
                    JSONObject rss_app = (JSONObject) rss_parser_app; 
                    
                    
                    
                    
                    
                    JSONArray rule_set_array_human = (JSONArray) rss_app.get("objects");
                    
                    if (rule_set_array_human.isEmpty())
                    {
                        break;
                        
                    }
                    
                    Iterator it = rule_set_array_human.iterator();
                    
                    JSONObject app_obj;// = new JSONObject();
                  
                    FileWriter file = new FileWriter("appdb.swa", false);
                    
                    while(it.hasNext())
                    {
                        
                        app_obj = new JSONObject(); 
                        
                        JSONObject current_app = (JSONObject) it.next();
                        String uid = (String)current_app.get("uid");
                        String name = (String)current_app.get("name");
                        
                        String category_primary = (String)current_app.get("primary-category");
                        String description = (String)current_app.get("description");
                        String risk = (String)current_app.get("risk");
                        JSONArray category_additional = (JSONArray) current_app.get("additional-categories");
                        Long appid = (Long)current_app.get("application-id");
                        
                        app_obj.put("name", name);
                        app_obj.put("uid", uid);
                        
                        app_obj.put("application-id", appid);
                        app_obj.put("risk", description);
                        app_obj.put("primary-category", category_primary);
                       

                        app_obj.put("additional-categories", category_additional);

                        count++;

                        
                        // pobierz aplikacje dopisane do aplikacji
                        
                      //  if (((application_list == null)) || (application_list.isEmpty()))
                        {
                            // lista aplikacji jest pusta lub nie ma takiego opiektu
                            ArrayList<String> application_list = categories.get(category_primary);
                                                   
                       if (application_list == null)
                       {
                           application_list = new ArrayList<>();
                           
                       }
                            
                            
                            application_list.add(name);     // dodajemy analizowaną aplikację. 
                            categories.put(category_primary, application_list);
                            
                            if (category_additional != null)
                            {
                                Iterator additer = category_additional.iterator();

                                while(additer.hasNext())
                                {
                                    String additional_category = (String) additer.next();
                                    application_list = categories.get(category_primary);
                                    application_list.add(name);     // dodajemy analizowaną aplikację. 
                                    categories.put(category_primary, application_list);

                                }

                            }
                            
                            
                        }
                        // pobieramy informacje o serwisach 
                        
                        
                      
                    //    String reguest_generic = Mgmt_API_body_builder_show_generic_object(uid);
                   //     String response_body_generic = Mgmt_API_REST_Call("show-generic-object", reguest_generic);
                    
                  //      Object rss_parser_generic = new JSONParser().parse(response_body_generic);     
                  //      JSONObject rss_generic = (JSONObject) rss_parser_generic; 
                    
                        
                  //      JSONArray app_services = (JSONArray) rss_generic.get("services");
                  //      Iterator iter = app_services.iterator();
                        
                 //       JSONObject service_obj = new JSONObject();
                        
                        int ser = 0;
                  //      while(iter.hasNext())
                        {
                            
                    //        JSONObject service = (JSONObject) iter.next();
                    //        String service_uid = (String) service.get("serviceUuid");
                    //        String service_type = (String) service.get("type");
                    //        String range =  (String) service.get("range");
                            
                            
                    //        service_obj.put("serviceUuid", service_uid);
                   //         service_obj.put("type", service_type);
                    //        service_obj.put("range", range);
                   //         ser++;
                  //          app_obj.put("services", service_obj);
                         //   System.out.println(" > " + ser + " " + service_uid );
                        }
                        
                        
                        
                        app_obj.put("description", description);
                        
                        
                        
                        
                        file.write(app_obj.toJSONString());
                        file.write("\n");
                        
                        
                       
                    }
                    
                    file.close();
                    
                    
                } 
                
                

                
                String reguest_body_category = Mgmt_API_body_builder_show_categories();
                String response_body_category = Mgmt_API_REST_Call("show-application-site-categories", reguest_body_category);
                    
                Object rss_parser_category = new JSONParser().parse(response_body_category);     
                JSONObject rss_category = (JSONObject) rss_parser_category; 
                    
                JSONArray category_list = (JSONArray) rss_category.get("objects");
                
                Iterator icat = category_list.iterator();
                
                JSONObject cat_obj;
                
                FileWriter cat_file = new FileWriter("catdb.swa", false );
                BufferedWriter bw_cat_file = new BufferedWriter(cat_file) ;
                
                while(icat.hasNext())
                {
                        cat_obj = new JSONObject();
                        
                        JSONObject json_category = (JSONObject) icat.next();
                        String catname = (String) json_category.get("name");
                        cat_obj.put("name", catname);
                        
                        
                                                
                        ArrayList<String> application_list = categories.get(catname);
                       
                        if (application_list == null)
                        {
                          
                            continue;
                            
                        }

                       Iterator appi =  application_list.iterator();
                     
                       Set<String> app_list_array = new HashSet<String>();
                     //  Hashset<String, String>  abc;
                   //   Hashmap<String, String> app_list_array = new ArrayList<>();
                     
                       while(appi.hasNext())
                       {
                           String app_name = (String) appi.next();    
                           app_list_array.add( app_name);
                        
                           
                       }
                       
                       CheckPoint_Management_API_Object_Processor temp = new CheckPoint_Management_API_Object_Processor();
                       CheckPoint_Management_API_Object_Processor.url_category url_cat_to_file;
                       
                       url_cat_to_file = temp.new url_category();
                       
                       url_cat_to_file.name = catname;
                       url_cat_to_file.apps =  app_list_array.toArray(new String[0]);
                      
                       Gson gson = new Gson();
                       String json_string_to_file;
                       
                       json_string_to_file = gson.toJson(url_cat_to_file);
                       bw_cat_file.write(json_string_to_file + "\n");
                        //cat_obj.put("apps", app_list_array);
                        //cat_file.write(cat_obj.toJSONString());
                        //cat_file.write("\n");
                   
              
                }
                    
                bw_cat_file.close();
                
                log_handler.log_in_gui(" Building APP Database. Done. \n", "" , "");
                
                
            }
            catch (Exception e)
            {
            
                log_handler.log_in_gui("(MAPAD) ERROR:"  + e.getLocalizedMessage() + "\n", "246556" , "");

                
                
            }
            
            
            
            
        }
        
        
        public void Mgmt_API_Process_Ruleset(String layer_name, boolean clear_grid, String rule_number_prefix , boolean with_inline_layers, String firewall_name)
        {
            
            try
            {
            
            
            if ( !API_Still_Connected())
            {
                // not connected
                
                API_Login();
                
                
            }
            
            // stil connected 
            
            //
            //
            //  analyze whole ruleset 
            //
            //
      


            long rules_total = 1;     // wszystkie regulu w zestawie
            long to = 0;             // obecnie przekazane reguly
            long from = 0;
            int offset = 0;
           
         
         

            // nowa lista regul
            if (rule_set == null)
            {
                rule_set =  new ArrayList(); 
            }
            
            if (clear_grid == true)
            {
                
                rule_set =  new ArrayList();
            }
            
            
            CheckPoint_Management_API_Rule_Processor rule_processor_handler = new CheckPoint_Management_API_Rule_Processor();
            rule_processor_handler.log_handler = log_handler;
            
            CheckPoint_Management_API_Rule_View api_rule_view_processor = new CheckPoint_Management_API_Rule_View();
            
            api_rule_view_processor.merge_jtable(GUI_Ruleset_Table, table_columns);
            api_rule_view_processor.log_handler = log_handler;            
            
            CheckPoint_Management_API_Rule_Processor tmp_rule_procesor = new CheckPoint_Management_API_Rule_Processor();
            CheckPoint_Management_API_Rule_Processor.Firewall_rule current_firewall_rule;
                    
           // fill object details
           current_firewall_rule = tmp_rule_procesor.new Firewall_rule();
            
            
            if (clear_grid == true)
            {
              
                DefaultTableModel remove_table_model = (DefaultTableModel) GUI_Ruleset_Table.getModel();
                remove_table_model.setRowCount(0);

                
            }

            DefaultTableModel GUI_Ruleset_Table_Model = (DefaultTableModel) GUI_Ruleset_Table.getModel();

            
            
            Object_Processor_Handler.prepare_global_set();
            Object_Processor_Handler.FIREWALL_to_analyze = firewall_name;
            Object_Processor_Handler.log_handler = log_handler;
            FIREWALL_to_analyze = firewall_name;
            Policy_Processor_Handler.FIREWALL_to_analyze = FIREWALL_to_analyze;
            
          
            Object_Processor_Handler.merge_server_paremeters(Mgmt_API_Server_IP, Mgmt_API_Server_Port, Mgmt_API_Server_User, Mgmt_API_Server_Password, Mgmt_API_Server_Auth_Token,  API_Client);        
            Policy_Processor_Handler.merge_Object_Procesor(Object_Processor_Handler);   
            Policy_Processor_Handler.log_handler = log_handler;

            log_handler.refresh_log_area();         
            
            // offset handling
            while (rules_total != to)
            {

                // human view - object names
                // machine view - range view


                // build query
                String request_body_human = Mgmt_API_body_builder_show_rule_set_human_view(layer_name, offset);         // widok ludzki
                log_handler.log_in_gui("[DEBUG] (MAPR) " + request_body_human, "41426" , request_body_human + "\n" );

                // send request
                String response_body_human = Mgmt_API_REST_Call("show-access-rulebase", request_body_human);      
                log_handler.log_in_gui("[DEBUG] (MAPR) " + response_body_human, "99525", response_body_human + "\n" );

                try
                {
                
                    Object rss_parser_human = new JSONParser().parse(response_body_human);     
                    JSONObject rss_human = (JSONObject) rss_parser_human; 

                    rules_total = (long)rss_human.get("total");
                    from = (long)rss_human.get("from");
                    to = (long)rss_human.get("to");


                    double percent =  ( (double)  ((double)to / (double)rules_total) * 100);
                    int int_percent = (int) percent;
     
                      
                    log_handler.log_in_gui("Progress: " + layer_name + " " + int_percent + "%\n" , "" , "" );
                    log_handler.refresh_log_area();

                    JSONArray rule_set_array_human = (JSONArray) rss_human.get("rulebase");
                    Iterator i = rule_set_array_human.iterator();
                    
                    while (i.hasNext()) 
                    {
   
                        JSONObject current_rule_object_human = (JSONObject) i.next();
                        String rule_type = (String)current_rule_object_human.get("type");
                 
    
                        if (rule_type.equals("access-section"))
                        {
                            // regula moze byc samodzielna 
                            // albo byc acces section wtedy kolejne zagniezdzenie 
                            
                            // rule processing here
                                          
                            Firewall_rule processed_rule = Policy_Processor_Handler.process_section(current_rule_object_human, layer_name);     
                            rule_set.add(processed_rule);
                            
                            if ( !processed_rule.uid.equals(last_section_uid))
                            {
                                
                                    // add section                            
                                    api_rule_view_processor.prepare_section_view(processed_rule);
                   
                            }
                            
                            last_section_uid = processed_rule.uid;
                        
                            JSONArray sub_rule_set_array_human = (JSONArray) current_rule_object_human.get("rulebase");
                            Iterator sub_i = sub_rule_set_array_human.iterator();
                    
                            
                            while (sub_i.hasNext()) 
                            {
            
                                    JSONObject current_sub_rule_object_human = (JSONObject) sub_i.next();
                                     
                                    String sub_rule_name = (String)current_sub_rule_object_human.get("name");      
                          
                                    // rule processing here

                                    Firewall_rule current_rule =  Policy_Processor_Handler.process_rule(current_sub_rule_object_human , rule_number_prefix, layer_name);   
                                    rule_set.add(current_rule);
                                    api_rule_view_processor.prepare_rule_view(current_rule, true);
                          
                                    
                                     if ((!current_rule.action_layer.equals("")) && (with_inline_layers == true))
                                     {
                                          // przescie do inline layer
                                          // trzeba zaladowac nowy ruleset i wrocic do starego
                                           Mgmt_API_Process_Ruleset(current_rule.action_layer,  false, current_rule.number + ".", true, firewall_name);
                                

                                      }
                                    
                 
                            }

                        }
                        else
                        {
                            
                            // rule without access section
                            // brak sekcji
                            
                            String rule_name = (String)current_rule_object_human.get("name");      
                                                
                            Firewall_rule current_rule = Policy_Processor_Handler.process_rule(current_rule_object_human , rule_number_prefix, layer_name);
                            rule_set.add(current_rule);
                            api_rule_view_processor.prepare_rule_view(current_rule, true);
                       
                            
                           if ((!current_rule.action_layer.equals("")) && (with_inline_layers == true))
                           {

                                Mgmt_API_Process_Ruleset(current_rule.action_layer,  false, current_rule.number + ".", true, firewall_name);
                                
                           }
                                    
                            
                        }
                        
   
                        log_handler.refresh_log_area();

                    }
                 
                        
                }
                catch (Exception e)
                {
                    
                    log_handler.log_in_gui("(MAPR) Error: " + e.getLocalizedMessage(), "74438" , layer_name + " " + rule_number_prefix + " " + firewall_name);
                    System.out.println("(MAPR) Error: " + e.getLocalizedMessage());
                    System.out.println("(MAPR) Error: " + e.getStackTrace());
                    
                }
   
                offset++;

            }

            }
            
        catch (Exception e)
        {

            log_handler.log_in_gui("(MAPR) ERROR:"  + e.getLocalizedMessage() + "\n", "246556" , layer_name + " " + rule_number_prefix + " " + firewall_name);

        }

            
       }


        
}
