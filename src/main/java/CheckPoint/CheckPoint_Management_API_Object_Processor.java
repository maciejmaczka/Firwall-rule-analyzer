/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint;

import CheckPoint.CheckPoint_Management_API_Rule_Processor.Object_network_range;
import CheckPoint.CheckPoint_Management_API_Rule_Processor.Object_service_range;
import CheckPoint.Windows.CheckPoint_Network_Object_Dictionary_Window;
import General.Log;
import com.google.gson.Gson;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import java.util.StringTokenizer;
/**
 *
 * @author Maciej
 */
public class CheckPoint_Management_API_Object_Processor
{

    public CheckPoint_Management_API_Object_Processor()
    {
        
     
    }
    
    // mandatory objects
    
    CheckPoint_Management_API_Rule_Processor.Object_network dictionary_network_object;
    CheckPoint_Management_API_Rule_Processor.Object_network_range dictionary_network_range_object;
    
    // log oparations, log to gui, and file
    public Log log_handler;

    
    // name of firewall
    public String FIREWALL_to_analyze = ""; 
    
    
    
    
    // connection handling. object hadnler manages api call by himself
    
    String Mgmt_API_Server_IP = "";
    String Mgmt_API_Server_Port = "";
    String Mgmt_API_Server_User = "";
    String Mgmt_API_Server_Password = "";
    String User_Agent = "Black-Wall-SI";
    
    
    boolean Mgmt_API_Server_Ignore_Cert = true;     
    String Mgmt_API_Server_Auth_Token  = "";
         
    
    // http connection handlers
    HttpClient API_Client;        
    HttpHost MGMT_Server;
     
    public class url_category
    {

     String name;
     String[] apps;



    }

    
    // object explorer all objects in one place
    public CheckPoint_Network_Object_Dictionary_Window network_object_explorer;        

    
    // network object set. stores all network objects
    Set<general_network_object>  network_object_set =  new HashSet(); 
    Set<ranges> dynamic_object_ranges_local_facts = new HashSet<>();
    Set<ranges> updatable_object_ranges_local_facts = new HashSet<>();
    public HashMap<String, Integer> identity_awareness_local_facts;
    Set<ranges> domain_objects_ranges_local_facts = new HashSet<>();
    public HashMap<String, String> application_match_overide;
    Set<url_category> url_category_database;// = new HashSet<>();
    
    
    // temporary netowork set. to story ranges only for current rules
    Set<CheckPoint_Management_API_Rule_Processor.Object_network_range>  temporary_network_range_set;
    Set<CheckPoint_Management_API_Rule_Processor.Object_service_range>  temporary_service_range_set;
    

    
    // apllication match overide  DONT ASK.
    public String web_services_group_uid = "aa159ad3-e324-4a43-9511-c06c15120ce7";
    public String[] web_services_default_group = {"http", "https", "HTTPS_proxy" , "HTTP_proxy" };
    
    
    
    
    
    
    public class general_network_object
    {
        // wlasna klasa dla obiektow
        // jeden obiekrt reprezentujacy wszystkie mozeliwosc jezeli chodzi o typy obiektow - host, network. range itp.
        
        
        public String uid = "";
        public String name = "";
        public String type = "";
        public String address = "";
        
        public String network = "";
        public String network_mask = "";
        
        public String ipv4_mask_wildcard = "";
        
        public String range_start = "";
        public String range_end = "";
        
        public ranges[] dynamic_object_ranges;      // lista adresow wyciagnieta z obiektow dynamicznych
        public ranges[] updatable_object_ranges;    // lista adresow wyciagnieta z aktualizujacych sie
        public ranges[] domain_object_ranges;       // lista adresow wyciagnieta z domen dns
        
        public boolean webserver = false;       // opcja dla hostow
        public boolean mailserver = false;      // opcja dla hostow 
        public boolean dnsserver = false;       // opcja dla hostow

        public String nat_address ;
        public String install_on = "";
        public String method = "";

        public String[] member_of ;    // jestem czlonkiem grupy  // member
        public members[] members ;      /// mam w sobie czlonkow // groups
        
        public ckp_interface[] interfaces;     // dla check pointow, hostow, inteopratable devices - informacja o interfejsach 
        public cluster_member[] cluster_members;  // dla check point - informacja o memberach klastra
        public String interface_name;           // dla strefy
        
        public String logical_server_group;
        
        public String include_group;   // na cele group with exclusion
        public String exclude_group;
        
        
        public String local_config = "";
        public String json = "";
        public String comment = "";
        
        public int identity_count = 0;  // ilosc obiektw pod access rola. Gubi informacje o uzytkownikow ale chcemy wiedziec ile ich jest do celow wydajnosciowych
        
        
   
        // service part ----------------------------------
        
        public String port_start = "";
        public String port_end = "";
        
        public String protocol = "";
        public String icmptype = "";
        
        public boolean match_protocol = false;
        public boolean cluster_sync = false;
        
        // ----------------------------------------------
        
        // application 
        
        public String primary_catergory = "";
        public String risk = "";
        public String[] application_service_ranges;
        public boolean negate_app_services;
        public String app_id = "";
        
        
                
                
        
        
        
        
        
    }
    
    public class ranges
    {
        public String name;
        public String range_start;
        public String range_end;
        public String local_config;
        public String number;
        
    }
    
    public class cluster_member
    {
        
        public String name = "";
        public String address = "";
        public String type = "";
        public ckp_interface[] interfaces; 
        
    }
    
    
    public class members
    {
        public String uid = "";
        public String name = "";
        public String type = "";
        
    }
    
    public class antispoofing
    {
        
        public String name = "";
        public String type = "";
        public String address = "";
        public String subnet = "";
        
    }
    
    public class ckp_interface
    {
        
        public String name = "";
        public String address = "";
      
        
        
        
        
    }
            
    
    public  Set<general_network_object> get_network_object_set()
    {
        
        
        return network_object_set;
        
    }
    
    
    public void show_network_object_dictionary()
    {
        // pokaz okineczko z obiektami jakie sa uzyte w konfiguracji.
        
        
         if (network_object_explorer == null)
         {
             
             log_handler.log_in_gui("Objects not loaded. Please use Connect -> Management API \n" , "" , "");
             
         }
         else
         {  
      
            network_object_explorer.setVisible(true);
            
         }
    }
    
    

    
 
    public void merge_server_paremeters( String Mgmt_API_Server_IP, String Mgmt_API_Server_Port, String Mgmt_API_Server_User, String Mgmt_API_Server_Password,String Mgmt_API_Server_Auth_Token , HttpClient API_Client  )
    {
        // przesylamy informacje o poleczeniu i juz stad wykonujemy polaczenia. 
        
        
        this.Mgmt_API_Server_IP = Mgmt_API_Server_IP;
        this.Mgmt_API_Server_Port = Mgmt_API_Server_Port;
        this.Mgmt_API_Server_User = Mgmt_API_Server_User;
        this.Mgmt_API_Server_Password = Mgmt_API_Server_Password;
        
        this.Mgmt_API_Server_Auth_Token = Mgmt_API_Server_Auth_Token;
        
        this.API_Client = API_Client;
      
        
        
    }
    
    public void prepare_global_set()
    {
        
        //  inicjalizacja hashlisty. 
        
        if (network_object_set == null)
        {
            network_object_set = new HashSet<general_network_object>();
        }
        network_object_explorer.merge_object_set(network_object_set);
 
        if (url_category_database == null)
        {
            
            
            load_category_database();
        }
        
        
    }
    
    public void load_category_database()
    {
        
          
         try
         {
            url_category_database = new HashSet<>();
           
            
            FileInputStream fis_object =new FileInputStream("catdb.swa");       
            Scanner sc_object =new Scanner(fis_object);
            Gson gson = new Gson();
        
            String gno_string;            
            url_category gno;
            while(sc_object.hasNextLine())  
            {
                
                gno_string = sc_object.nextLine();
                gno = gson.fromJson(gno_string,url_category.class );
                url_category_database.add(gno);
                
            }
            
            sc_object.close();
            
          
            
         }
         catch (Exception e)
         {
             
              log_handler.log_in_gui("(LCD) ERROR: " + e.getLocalizedMessage() , "646070" , "" );
            
             
         }       
        
    }
    
     
    public String Mgmt_API_Object_get_by_name(String name)
    {
        
        // tworzymy request body 
        // pobieramy wartosc przez nazwe
        
            Map<String,String> API_Body = new HashMap<String,String>();
            API_Body.put("name", name);


            JSONObject API_Body_json = new JSONObject(API_Body);
            String body_string = API_Body_json.toJSONString();

            
            return body_string;
        
    }
    
   
      
        public String Mgmt_API_Object_get_by_by_id(String uid)
        {

        // tworzymy request body 
        // pobieramy wartosc przez uid


            Map<String,String> API_Body = new HashMap<String,String>();
            API_Body.put("uid", uid);


            JSONObject API_Body_json = new JSONObject(API_Body);
            String body_string = API_Body_json.toJSONString();

            
            return body_string;

        }
    
 
        public String check_if_object_exist_in_object_store(String name, String uid,  String type)
        {
          
            
            String json_from_store = find_object_in_dictionary_set(name, type);
            
         
            if (json_from_store != null)
            {
               
              
                return json_from_store;
                
                
            }
            else
            {
                
                json_from_store = find_object_in_dictionary_set(uid, type);
                
                if (json_from_store != null)
                {
                 
                    return json_from_store;
                    
                }
              //  else
                {
               
                    return null;
                    
                }
                
            }
            
          
        }
   
          // standardowe wyslanie zapytania
        public String Mgmt_API_REST_Call(String function, String body_string, String name, String uid, String type)
        {

            
            //
            //
            //  standard REST API CALL
            //  Used everywhere
            //
            // ta sama funkcje jest uzyta w innych miejscach. 


            // sprawdzic czy polaczenie jeszcze jest wazne 

            String response_string = "";
            
            try
            {

                    // sprawdzanie cache
                    // zmniejszenie ilosci zapytan do serwera
                    String json_from_store =  check_if_object_exist_in_object_store(name, uid, type );

                    if (json_from_store != null)
                    {


                         return json_from_store;

                    }

                                //
                // HEADER 
                //
                Thread.sleep(100);
                       
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
               response_string = EntityUtils.toString(API_Response.getEntity());
               

               return response_string;
               
               

            }
            catch (Exception e)
            {
               

                log_handler.log_in_gui("(MARC) ERROR:"  + e.getLocalizedMessage() + "\n" ,"28898", function + " " + body_string + " " + response_string );
                

                return null;
                
                
            }
            


        }

        
         public general_network_object read_group(String json_response)
        {
            
            // handle group properties
            
            try
            {
                
            // czytamy tylko wartosci ktore nas interesuja.
            // splaszczamy klase, dlatego recznie. 
            
            general_network_object current_object = new general_network_object();
            
            Object rss_parser = new JSONParser().parse(json_response);     
            JSONObject js_current_object = (JSONObject) rss_parser; 
            
            current_object.uid = (String) js_current_object.get("uid");
            current_object.name = (String) js_current_object.get("name");
            current_object.type = (String) js_current_object.get("type");
            current_object.comment = (String) js_current_object.get("comment");
            current_object.json = json_response;            
            
            JSONArray members_array = (JSONArray) js_current_object.get("members");  
            Iterator i = members_array.iterator();
            int array_size = members_array.size();
            
            current_object.members = new members[array_size];
            int val = 0;
           
            if (array_size  != 0)
            {
                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();
                    current_object.members[val] = new members();
                    
                    current_object.members[val].name =  (String) group.get("name");
                    current_object.members[val].type =  (String) group.get("type");
                    current_object.members[val].uid =  (String) group.get("uid");
                    val++;
                    
                  
                }           
            }
               
            JSONArray group_array = (JSONArray) js_current_object.get("groups");  
            i = group_array.iterator();
            array_size = group_array.size();
            
            
            // do zastanowienia sie czy to chcemy
            /*
            current_object.member_of = new String[array_size];
            val = 0;
           
           
            while (i.hasNext()) 
            {
                
                JSONObject group = (JSONObject) i.next();
                
                current_object.member_of[val] =  (String) group.get("name");
                
                val++;
                
            }
            
            */
            
            return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RG) Error: " + json_response + " " + e.getMessage(), "54095", json_response);
                return null;
            }
            
           
                
        }
  
        public general_network_object read_category(String json_response)
        {

            try
            {
                
                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;      
                
                // tymczasowa lista
                HashMap<String, String>  service_list_tmp = new HashMap< String, String>(); 
                
                
                
                // nie zaczytano lokalnego konfigu 
                if ((application_match_overide == null)  || (application_match_overide.size() == 0))
                {
             
                    // brak lokalnego overidu
                    // brak zmiany w domyslnych portach
                    // ladujemy recznie to co powinno byc zaladowane
                    //  PROTO/NUMER/PORT/NAZWA
                    // zapis dziwaczny ze wzgledu na kilka sposobow zapisu konfiguracji
                    
                    String put  = "TCP" +"/"+ "6" + "/" + "80" + "/" + "Default " + "TCP" + " " + "80"  +  ";";
                    service_list_tmp.put(put , put);

                    put  = "TCP" +"/"+ "6" + "/" + "8080" + "/" + "Default " + "TCP" + " " + "8080"  +  ";";
                    service_list_tmp.put(put , put);

                    put  = "TCP" +"/"+ "6" + "/" + "443" + "/" + "Default " + "TCP" + " " + "443"  +  ";";
                    service_list_tmp.put(put , put);

                }
                else
                {
                    
                    // wykonano lokalny overide
                    // infomacje zaczytane z lokalnej konfiugracji firewalla
              
                    
                    String web_services = application_match_overide.get(web_services_group_uid);

                    
                    web_services = web_services.replaceAll(";;false", "");
                    String[] web_services_group = web_services.split(";");


                    for (int s = 0 ; s < web_services_group.length ; s++)
                    {
                       // odczyt inforamcji zaczytanych z lokanej konfiguracji.
                       
                        
                       String line = read_service_for_application( web_services_group[s] );


                       line = line.replace("service-tcp", "TCP");
                       line = line.replace("service-udp", "UDP");
                       line = line.replace("service-other", "Other");
                       line = line.replace("service-dce-rpc", "DCE-RPC");


                       line = line.replace("tcp", "TCP");
                       line = line.replace("Tcp", "TCP");
                       line = line.replace("udp", "UDP");
                       line = line.replace("Udp", "UDP");
                       line = line.replace("other", "Other");
                       line = line.replace("Other", "Other");

                       // zapis na liste aby uniknac duplikatow                   
                       service_list_tmp.put(line , line);  

                    
                    }
                    
                    
                }
  
                current_object.application_service_ranges = new String[service_list_tmp.size()];


                Iterator keySetIterator = service_list_tmp.keySet().iterator();
                int j = 0;


                // skopiowanie listy na obiekt array
                while (keySetIterator.hasNext())
                {
                    String key = (String) keySetIterator.next();

                    current_object.application_service_ranges[j] = key;

                    j++;

                }

              
                
                return current_object;
                
            }
            catch (Exception e)
            {
                log_handler.log_in_gui("(RC) Error: " + json_response + " " + e.getMessage(), "447840", json_response);
                return null;
                
            }
            
            


        }
         
         
         public general_network_object read_service_object(String json_response)
         {
            
             try
             {
                 
                 // wszystkie service tcp udp icmp other czytamy za pomoca jednej funkcji
             
                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;      
                
     
                    
                
                current_object.port_start = (String) js_current_object.get("port");
                
                
                // kilka sposobow zapisu pola port  80   ;  80-81 ; ANY; null
                
                if ((current_object.port_start == null) ||  (current_object.port_start.equals("")))
                {
                    
                    current_object.port_start = "Any";
                    current_object.port_end = "Any";
                    
                }
                else
                {
                    if (current_object.port_start.contains("-"))
                    {
                        String tmp = current_object.port_start;
                        current_object.port_start = tmp.substring(0,tmp.indexOf("-") );
                        current_object.port_end = tmp.substring(tmp.indexOf("-") + 1, tmp.length());

                    }
                    else
                    {
                        current_object.port_end = current_object.port_start;

                    }
                }

                
                // numer protokolu dla nie tcp i udp
                
                if (current_object.type.equals("service-other"))
                {
                        Long proto_tmp = (Long) js_current_object.get("ip-protocol");
                        current_object.protocol = proto_tmp.toString();
                    
                }
                else
                {
                
                        current_object.protocol = (String) js_current_object.get("protocol");
        
                }
                
                
                if (current_object.type.equals("service-tcp"))
                {
                    
                    current_object.protocol = "6";
                    
                }

                if (current_object.type.equals("service-udp"))
                {
                    
                    current_object.protocol = "17";
                }
                
                if (current_object.type.equals("service-icmp"))
                {
                    
                    current_object.protocol = "1";
                }

                if (current_object.type.equals("service-rpc"))
                {
                    
                    current_object.protocol = "-1";
                }
                
                if (current_object.type.equals("service-dce-rpc"))
                {
                    
                    current_object.protocol = "-1";
                }
                
                // zapis ochronny przed null
                
                if (Boolean.TRUE.equals((Boolean) js_current_object.get("match-by-protocol-signature")))
                {
                    current_object.match_protocol = true; 
                }
                else
                {
                    current_object.match_protocol = false;
                }
                
                // zapis ochronny przed null
                if (Boolean.TRUE.equals((Boolean) js_current_object.get("sync-connections-on-cluster")))
                {
                    current_object.cluster_sync = true; 
                }
                else
                {
                    current_object.cluster_sync = false;
                }
                
                
                Long tmp  = ((Long) js_current_object.get("icmp-type"));
                 if (tmp == null)
                 {
                     current_object.icmptype = "";
                     
                 }
                 else
                 {                   
                    current_object.icmptype = tmp.toString();                
                 }
                 
                

             return current_object;
             
             
             }
             catch (Exception e)
            {
                log_handler.log_in_gui("(RSO) Error: " + e.getLocalizedMessage() , "163090" , json_response);
                return null;
            }
                     
             
         }
         
         
          public general_network_object read_applicaiton_site_object(String json_response)
         {
          
             try
             {
    
                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;  
                 
                 
                Long app_id_temp = (Long) js_current_object.get("application-id");              
                if (app_id_temp == null)
                {
                
                    current_object.app_id = "";
                }
                else
                {
                    current_object.app_id = app_id_temp.toString();
                }
                   
                
                
                String tmp = application_match_overide.get(current_object.uid);
                
                Boolean user_defined = (Boolean) js_current_object.get("user-defined");
                

                
                if  ((tmp == null) || (tmp.length() == 0 ))
                {
                    
                    // standardowa konfiguacjia
                    // brak zmian na lokalnym firewallu
                    
                    String api_query_body = Mgmt_API_Object_get_by_by_id(current_object.uid);                  
                    String api_query_respond = Mgmt_API_REST_Call("show-generic-object" , api_query_body, "" , current_object.uid, "generic-object");                      
              
                    
                    // do celow cache
                    
                    general_network_object generic = new general_network_object();
                    generic.name = current_object.uid;
                    generic.uid = current_object.uid;
                    generic.type = "generic-object";
                    generic.json = api_query_respond;
                    add_general_network_object_to_dictionary_set(generic);
                    
                    
                        // odpytywanie sie do wlasciwosci obiektu poprzez generic object i przeczytanie services
                         
                    Object rss_generic_parser = new JSONParser().parse(api_query_respond);     
                    JSONObject js_generic_current_object = (JSONObject) rss_generic_parser; 
                  
                    JSONArray members_array = (JSONArray) js_generic_current_object.get("services");  
                    
                    
                    if (members_array == null)
                    {
                        

                    }
                    else
                    {
                    
                        HashMap<String, String>  service_list_tmp = new HashMap< String, String>(); 
                        
                        Iterator i = members_array.iterator();
                        JSONObject services; 
                        while (i.hasNext())
                        {
                            
                            services = (JSONObject) i.next();
                            String type = (String) services.get("type");
                            String uid = (String) services.get("serviceUuid");
                            String range = (String) services.get("range");

                            // co jest domyslnym serwisem dla aplikacji 
                            
                            
                            // czesc informacji zapisanych w postaci grupy , gdzie moze byc overide
                            // czesc inforamcji zapisuanych w postaci pojedynczego servicu, gdzie moze byc overide
                            // czesci inforamcji w postaci adnotacji do groupy web services , gdzie moze byc overide
                            
                            if (type.equals("group"))
                            {
                                if (user_defined == true)
                                {
                                    
                                    uid = web_services_group_uid;
                                    
                                }
                                
                                String web_services = application_match_overide.get(uid);

                                
                                if ((web_services == null ) && (uid.equals(web_services_group_uid)))
                                {
                                    
                                    // default ports used ovveride not loaded                              
                                    String put  = "TCP" +"/"+ "6" + "/" + "80" + "/" + " " + "TCP" + " " + "80"  +  ";";
                                    service_list_tmp.put(put , put);
                                    
                                    put  = "TCP" +"/"+ "6" + "/" + "8080" + "/" + " " + "TCP" + " " + "8080"  +  ";";
                                    service_list_tmp.put(put , put);
                                    
                                    put  = "TCP" +"/"+ "6" + "/" + "443" + "/" + " " + "TCP" + " " + "443"  +  ";";
                                    service_list_tmp.put(put , put);
                                    
                                }
                                else
                                {
                                // defeult port loaded from file    
                               //  System.out.println(current_object.name +  ">" + uid + " | " + web_services);
                                 
                                 if (web_services == null)
                                 {
                                     uid = "aa159ad3-e324-4a43-9511-c06c15120ce7";
                                     web_services = application_match_overide.get(uid);
                                 }
     
                                
                                 web_services = web_services.replaceAll(";;false", "");
                                 String[] web_services_group = web_services.split(";");
                                 
                                 
                                 for (int s = 0 ; s < web_services_group.length ; s++)
                                // grupa
                                 {
                                     String line = read_service_for_application( web_services_group[s] );
                                     
                                     
                                    line = line.replace("service-tcp", "TCP");
                                    line = line.replace("service-udp", "UDP");
                                    line = line.replace("service-other", "Other");
                                    line = line.replace("service-dce-rpc", "DCE-RPC");


                                    line = line.replace("tcp", "TCP");
                                    line = line.replace("Tcp", "TCP");
                                    line = line.replace("udp", "UDP");
                                    line = line.replace("Udp", "UDP");
                                    line = line.replace("other", "Other");
                                    line = line.replace("Other", "Other");
                                     
                                     service_list_tmp.put(line , line);  
                                
                                   
                                 }
          
                                }
                            }
                            else
                            {
                                // pojedyncze wpisy
                              String protocol = "";
                              
                              if (type.equals("tcp"))
                              {
                                  protocol = "6";
                                  type = "TCP";
                                  
                              }
                              
                              if (type.equals("udp"))    
                              {
                                   type = "UDP";
                                   protocol = "17";
                                  
                              }
                              
                              if (type.equals("other"))    
                              {
                              
                                  // brak informacji o protokole
                                  // trzeba pobierac reczenie
                                 //  type = "UDP";
                                 //  protocol = "17";
                                         
                                    String api_query_body_other = Mgmt_API_Object_get_by_by_id(uid);                  
                                    String api_query_respond_other  = Mgmt_API_REST_Call("show-service-other" , api_query_body_other, "" , uid, type );                      

                                    Object rss_parser_other  = new JSONParser().parse(api_query_respond_other);     
                                    JSONObject js_current_object_other  = (JSONObject) rss_parser_other; 

                                    Long protocol_long = (Long) js_current_object_other.get("ip-protocol");
                                    protocol = protocol_long.toString();    
                                    
                                    type = "Other";
                                    range = " ";  
                                  
                              }
                              
                              if (range.equals("default"))
                              {
                                  
                                   // inny parametr
                                  String origUid = (String) services.get("origUuid");
                                  
                                  
                                    String api_query_body_default = Mgmt_API_Object_get_by_by_id(origUid);                  
                                    String api_query_respond_default = Mgmt_API_REST_Call("show-generic-object" , api_query_body_default, "" , origUid , "generic-object");                      
                                    //general_network_object net_object = read_security_zone(api_query_respond);
                                    json_response = api_query_respond;


                                    general_network_object generic_default = new general_network_object();
                                    generic_default.name = uid;
                                    generic_default.uid = uid;
                                    generic_default.type = "generic-object";
                                    generic_default.json = api_query_respond_default;
                                    add_general_network_object_to_dictionary_set(generic_default);





                                    Object rss_parser_default = new JSONParser().parse(api_query_respond_default);     
                                    JSONObject js_current_object_default = (JSONObject) rss_parser_default; 

                                    range = (String) js_current_object_default.get("port");
                              }
                              
                            
                                                                                        // default
                              String put =   type +"/"+ protocol + "/" + range + "/" + " " + type + " " + range  +  ";";
                              
                              service_list_tmp.put(put , put);                    
                                                  
                            }
                            
                            
                         
                        }
                    
                    
                        current_object.application_service_ranges = new String[service_list_tmp.size()];

                        Iterator keySetIterator = service_list_tmp.keySet().iterator();
                        int j = 0;



                        while (keySetIterator.hasNext())
                        {
                            String key = (String) keySetIterator.next();                       
                            current_object.application_service_ranges[j] = key;                      
                            j++;

                        }

       
                    
                    }
                    
                    
                }
                else
                {
                    // local override
  
                    // check on all ports
                    
                    if (tmp.contains("Any"))
                    {
                        
                        current_object.application_service_ranges = new String[1];
                        current_object.application_service_ranges[0] = "Any/Any/Any/Any";
                        return current_object;
                        
                        
                    }
                    
                    // check on custom ports;
                    
                    
                    if (tmp.contains(";;true"))
                    {
                        
                        current_object.negate_app_services = true;
                        tmp = tmp.replace(";;true", "");
                    }
                   
                    if (tmp.contains(";;false"))
                    {
                        
                        current_object.negate_app_services = false;
                        tmp = tmp.replace(";;false", "");
                        
                    }
                    
                    HashMap<Integer, String>  service_list = new HashMap< Integer, String>(); 
             
                    String[] result = tmp.split(";");
                    
                    for ( int i = 0 ; i < result.length ; i++)
                    {
                        
                       String srv =  read_service_for_application(result[i] );
                       service_list.put(i, srv);
                        
                    }
                    
                    
                    HashMap<String, String>  service_list_tmp = new HashMap<String, String>(); 
                                      
                    for (int j = 0 ; j < service_list.size() ; j++)
                    {
                  
                        StringTokenizer st = new StringTokenizer(service_list.get(j) ,";");
                        
                         while (st.hasMoreTokens()) 
                         {
                             
                            String line = st.nextToken();
                            line = line.replace("service-tcp", "TCP");
                            line = line.replace("service-udp", "UDP");
                            line = line.replace("service-other", "Other");
                            line = line.replace("service-dce-rpc", "DCE-RPC");
                            
                            
                            line = line.replace("tcp", "TCP");
                            line = line.replace("udp", "UDP");
                            
                            service_list_tmp.put(line, line);
                            
                            
                            
                            
                         }
                    
                    
                    }
                    
                    
                    current_object.application_service_ranges = new String[service_list_tmp.size()];
                    
                    
                    Iterator keySetIterator = service_list_tmp.keySet().iterator();
                    int i = 0;
                    
      
                   while (keySetIterator.hasNext())
                    {
                        String key = (String) keySetIterator.next();                    
                        current_object.application_service_ranges[i] = key;           
                        i++;

                    }
        
                }


             return current_object;
             
             }
             catch (Exception e)
            {
                log_handler.log_in_gui("(RASO) Error: " + e.getLocalizedMessage() , "496935" , json_response);
                return null;
            }
                     
             
         }
         
         public String read_service_group_for_application(String name , String obj_type, String history)
         {
            
             
             String json_response = "";
             String return_string = history;
                
             try
             {
                 
                String api_query_body = Mgmt_API_Object_get_by_name(name);                  
                String api_query_respond = Mgmt_API_REST_Call("show-service-group" , api_query_body, name, "", "service-group");                      

                Object rss_parser = new JSONParser().parse(api_query_respond);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                       // do celow cache

               general_network_object generic = new general_network_object();
               generic.name = (String) js_current_object.get("name");
               generic.uid = (String) js_current_object.get("uid");
               generic.type = "service-group";
               generic.json = api_query_respond;
               add_general_network_object_to_dictionary_set(generic);



                JSONArray members_array = (JSONArray) js_current_object.get("members");  
                Iterator i = members_array.iterator();


                while(i.hasNext())
                {
                    JSONObject srv_jsn = (JSONObject) i.next();

                    String mem_name = (String) srv_jsn.get("name");
                    String type = (String) srv_jsn.get("type");

                    String port = (String) srv_jsn.get("port");

                    String protocol = "";


                    if (type.equals("service-group"))
                    {
                       return_string += read_service_group_for_application(mem_name , "service-group", return_string);
                    }
                    else
                    {
                       if ((type.equals("service-other")) || (type.equals("other")))
                       {                

                           // co to za protokol
                           // nie ma informacji o typie protokolu
                           // trzeba wywolac recznie
                           String api_query_body_other = Mgmt_API_Object_get_by_name(mem_name);                  
                           String api_query_respond_other  = Mgmt_API_REST_Call("show-service-other" , api_query_body_other, name, "" , "service-other");                      

                           Object rss_parser_other  = new JSONParser().parse(api_query_respond_other);     
                           JSONObject js_current_object_other  = (JSONObject) rss_parser_other; 

                           Long protocol_long = (Long) js_current_object_other.get("ip-protocol");
                           protocol = protocol_long.toString();

                           if ((port == null) || (port.length() ==0 ))
                           {
                               port = "ANY";
                           }

                           if ((protocol == null) || (protocol.length() ==0 ))
                           {
                               protocol = "ANY";
                           }

                            if ((type.equals("DCE-RPC")) || (type.equals("RPC")))
                           {
                               protocol = "ANY";
                               port = "ANY";
                           }


                            return_string += type +"/"+ protocol + "/" + port + "/" + mem_name  +  ";"; 

                    }
                    else
                    {
                        // reczne uzupelnianie danych ktorych brakuje

                        if (type.equals("service-tcp"))
                        {

                            protocol = "6";
                        }

                        if (type.equals("service-udp"))
                        {

                            protocol = "17";
                        }


                            protocol = "17";



                        if (type.equals("DCE-RPC"))
                        {

                            protocol = "ANY";
                            port = "ANY";

                        }


                        if ((port == null) || (port.length() ==0 ))
                        {

                            port = "ANY";

                        }

                        if ((protocol == null) || (protocol.length() ==0 ))
                        {

                            protocol = "ANY";

                        }

                          return_string += type +"/"+ protocol + "/" + port + "/" + mem_name  +  ";"; 
                    }
                 }


            }
            
            
             return return_string;
             
             
                 
             }
             catch (Exception e)
             {
                log_handler.log_in_gui("(RSGFA) Error: " + e.getLocalizedMessage() , "768430" , json_response);
                return null; 
                 
             }
             
         }
          
         public String read_service_for_application(String uid )
         {
                
             
                String json_response = "";
                
                try
                {
             
                    String api_query_body = Mgmt_API_Object_get_by_by_id(uid);                  
                    String api_query_respond = Mgmt_API_REST_Call("show-generic-object" , api_query_body, "" , uid , "generic-object");                      
                    //general_network_object net_object = read_security_zone(api_query_respond);
                    json_response = api_query_respond;

                                        
                    general_network_object generic = new general_network_object();
                    generic.name = uid;
                    generic.uid = uid;
                    generic.type = "generic-object";
                    generic.json = api_query_respond;
                    add_general_network_object_to_dictionary_set(generic);
                    
                    
                    
                    
                    
                    Object rss_parser = new JSONParser().parse(api_query_respond);     
                    JSONObject js_current_object = (JSONObject) rss_parser; 

                    String name = (String) js_current_object.get("name");
                    String type = (String) js_current_object.get("type");
                    String port = (String) js_current_object.get("port");
                    Long protocol_long = (Long) js_current_object.get("protocol");

                    String protocol = "";
                    if (protocol_long != null)
                    {
                        protocol = protocol_long.toString();
                    }
                    else
                    {

                         protocol = (String) js_current_object.get("_original_type");

                         if (protocol.equals("CpmiTcpService"))
                         {

                             protocol = "TCP";

                         }

                         if (protocol.equals("CpmiUdpService"))
                         {

                             protocol = "UDP";

                         }  

                         if (protocol.equals("CpmiServiceGroup"))
                         {

                             protocol = "group";

                         }
                    }


                    String return_string = "";

                    if ( type.equals("group"))
                    {


                       return_string += read_service_group_for_application(name , uid, "");
                       return return_string; 


                    }  


                    if ((port == null) || (port.length() ==0 ))
                    {

                        port = "ANY";

                    }

                    if ((protocol == null) || (protocol.length() ==0 ))
                    {

                        protocol = "ANY";

                    }

                    if ((type.equals("DCE-RPC")) || (type.equals("RPC"))) 
                    {

                        protocol = "ANY";
                        port = "ANY";

                    }



                    return_string = type +"/"+ protocol + "/" + port + "/" + name +  ";"; 

               
                return return_string;
                
                }catch (Exception e)
                {
                    
                    log_handler.log_in_gui("(RSFA) Error: " + e.getLocalizedMessage() , "353674" , json_response);
                    return null;
                    
                }
             
         }
        
         
         public general_network_object read_security_zone(String json_response , String rule_number)
        {
            
            // handle group properties
            
            try
            {
            
                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;            
                  
            

                 String firewall_type = check_checkpoint_object_type(FIREWALL_to_analyze);
           

                // pobierz informacje o obiekcie
                // tylko po to aby byl w network objectach
                calculate_object(FIREWALL_to_analyze,current_object.uid , firewall_type, 2, "network" , rule_number,  false);

                String js_firewall_to_analyze = find_object_in_dictionary_set(FIREWALL_to_analyze, firewall_type);

                // czytamy security zone

                Object rss_parser_firewall = new JSONParser().parse(js_firewall_to_analyze);     
                JSONObject js_firewall = (JSONObject) rss_parser_firewall; 

                JSONArray interface_array = new JSONArray();

                if (firewall_type.equals("simple-gateway"))
                {
                   interface_array = (JSONArray) js_firewall.get("interfaces");
                }

                if (firewall_type.equals("simple-cluster"))
                {

                     JSONObject interface_object = (JSONObject) js_firewall.get("interfaces");
                     interface_array = (JSONArray) interface_object.get("objects");
                }

                Iterator i = interface_array.iterator();
                int array_size = interface_array.size();

                int aspf = 0;
              
               current_object.interfaces = new ckp_interface[1];

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    
                    String interface_name =   (String) ckp_interface.get("name");
                    JSONObject zone_settings = (JSONObject) ckp_interface.get("security-zone-settings");

                    if (zone_settings != null)
                    {

                        String zone_name = (String) zone_settings.get("specific-zone");
                        
                        if (current_object.name.equals(zone_name))
                        {

                            if ( aspf >= current_object.interfaces.length)
                            {
                                // rozszerzamy tablice
                                //tablica tymczasowa
                                //System.out.println("pierwsze kopiowanie");
                                ckp_interface[] temp_interfaces = new ckp_interface[current_object.interfaces.length];                        
                                System.arraycopy(current_object.interfaces, 0, temp_interfaces, 0, current_object.interfaces.length);

                                //rozszerzamy tablice

                                 current_object.interfaces = new ckp_interface[current_object.interfaces.length + 1];
                                 System.arraycopy(temp_interfaces , 0, current_object.interfaces, 0, current_object.interfaces.length - 1);

 
                             }

                            current_object.address = "0.0.0.0";
                            current_object.network_mask = "0.0.0.0";
                            current_object.interfaces[aspf] = new ckp_interface();
                            current_object.interfaces[aspf].name = interface_name;

                           
                            aspf++;
                        
                 
                        
                    }
                    
                    
                }
             
      
            }
            
         
            return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RSZ) Error: " + e.getLocalizedMessage() , "40067" , json_response);
                return null;
            }
            
           
                
        } 
         

          public general_network_object read_group_with_exclusion(String json_response)
        {
            
                       
            try
            {

                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;            

                JSONObject include_group = (JSONObject) js_current_object.get("include");  
                current_object.include_group = (String) include_group.get("name");

                JSONObject exclude_group = (JSONObject) js_current_object.get("except");  
                current_object.exclude_group = (String) exclude_group.get("name");

                int val = 0;
           
                JSONArray group_array = (JSONArray) js_current_object.get("groups");  
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                val = 0;


                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();

                    current_object.member_of[val] =  (String) group.get("name");

                    val++;

                }
            
          
            
                 return current_object;
            
            } 
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(RGWE) Error: " + e.getMessage() , "74788", json_response);
                return null;
            }
            
           
                
        }
            
       public general_network_object read_ose_device(String json_response)
        {
            
            // handle host properties
            
            try
            {
            


                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("_original_type");
                current_object.address = (String) js_current_object.get("ipaddr");      
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;
            
         
            
                 JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 
            
                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }


                JSONArray interface_array = (JSONArray) js_current_object.get("interfaces");
                Iterator i = interface_array.iterator();
                int array_size = interface_array.size();

                current_object.interfaces = new ckp_interface[array_size];
                int val = 0;

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    current_object.interfaces[val] = new ckp_interface();
                    current_object.interfaces[val].name =  (String) ckp_interface.get("officialname");
                    current_object.interfaces[val].address =  (String) ckp_interface.get("ipaddr");
                    val++;

                }
            
       
                 return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(ROSE) Error: " + e.getLocalizedMessage() , "758582", json_response);
                return null;
            }
            
           
                
        }

       
                  
       public general_network_object read_interoperable_device(String json_response)
        {
            
            // handle host properties
            
            try
            {
            


                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("_original_type");
                current_object.address = (String) js_current_object.get("ipaddr");      
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;



                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }
            
                
                JSONArray interface_array = (JSONArray) js_current_object.get("interfaces");
                Iterator i = interface_array.iterator();
                int array_size = interface_array.size();

                current_object.interfaces = new ckp_interface[array_size];
                int val = 0;

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    current_object.interfaces[val] = new ckp_interface();


                    current_object.interfaces[val].name =  (String) ckp_interface.get("officialname");
                    current_object.interfaces[val].address =  (String) ckp_interface.get("ipaddr");
                    val++;

                }





                return current_object;

            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RIO) Error: " + e.getLocalizedMessage() , "517909", json_response);
                return null;
            }
            
           
                
        }

         
                         
       public general_network_object read_logical_server(String json_response)
        {
            
            // handle host properties
            
            try
            {
            


                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("_original_type");
                current_object.address = (String) js_current_object.get("ipaddr");      
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;
                current_object.logical_server_group = (String) js_current_object.get("servers"); // do podmianiany na nazwe
                
                String api_query_body_group = Mgmt_API_Object_get_by_by_id(current_object.logical_server_group);
                String api_query_respond_group = Mgmt_API_REST_Call("show-group" , api_query_body_group, "", "", "");  
                
                Object rss_parser_group = new JSONParser().parse(api_query_respond_group);     
                JSONObject js_current_object_group = (JSONObject) rss_parser_group; 

                current_object.logical_server_group = (String) js_current_object_group.get("name");                
                
                return current_object;

            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RIO) Error: " + e.getLocalizedMessage() , "517909", json_response);
                return null;
            }
            
           
                
        }

         
       
       public general_network_object read_host(String json_response)
        {
            
            // handle host properties
            
            try
            {
            
                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.address = (String) js_current_object.get("ipv4-address");      
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;

                JSONObject js_current_object_servers = (JSONObject) js_current_object.get("host-servers"); 
                if (js_current_object_servers != null)
                {

                    current_object.webserver = (boolean) js_current_object_servers.get("web-server");
                    current_object.dnsserver = (boolean) js_current_object_servers.get("dns-server");
                    current_object.mailserver = (boolean) js_current_object_servers.get("mail-server");

                }

                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 
            
                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }


                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;

                if (array_size != 0)
                {
                    while (i.hasNext()) 
                    {

                        JSONObject group = (JSONObject) i.next();

                        current_object.member_of[val] =  (String) group.get("name");

                        val++;

                    }

                }
            
            

                JSONArray interface_array = (JSONArray) js_current_object.get("interfaces");
                i = interface_array.iterator();
                array_size = interface_array.size();

                current_object.interfaces = new ckp_interface[array_size];
                val = 0;

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    current_object.interfaces[val] = new ckp_interface();


                    current_object.interfaces[val].name =  (String) ckp_interface.get("name");
                    current_object.interfaces[val].address =  (String) ckp_interface.get("subnet4");
                    val++;

                }
            
            
            
            
                  return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RH) Error: " + e.getLocalizedMessage() , "57847", json_response);
                return null;
            }
            
           
                
        }

         
        
                  
       
       
       
          public general_network_object read_range(String json_response)
        {
           
            
            try
            {

                general_network_object current_object = new general_network_object();

                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.range_start = (String) js_current_object.get("ipv4-address-first"); 
                current_object.range_end = (String) js_current_object.get("ipv4-address-last");      
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;



                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;

                if (array_size != 0)
                {
                    while (i.hasNext()) 
                    {

                        JSONObject group = (JSONObject) i.next();

                        current_object.member_of[val] =  (String) group.get("name");

                        val++;

                    }

                }
            
                return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RH) Error: " + e.getLocalizedMessage(), "49282", json_response);
                return null;
            }
            
           
                
        }

       
       
        
       public general_network_object read_dynamic_object(String json_response)
        {
            // read network settings
            
            
            try
            {

                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");

                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           

                // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }

               
                JSONArray group_array = (JSONArray) js_current_object.get("groups");

                if (group_array != null)
                {
                    Iterator i = group_array.iterator();



                    int array_size = group_array.size();

                    current_object.member_of = new String[array_size];
                    int val = 0;


                    while (i.hasNext()) 
                    {

                        JSONObject group = (JSONObject) i.next();

                        current_object.member_of[val] =  (String) group.get("name");

                        val++;

                    }
                }

            
            // sprawdz czy obiekt istnieje w lokalnej konfiguracji
            
            
                Iterator liter = dynamic_object_ranges_local_facts.iterator();
                int ranges_found = 0;

                while(liter.hasNext())
                {

                    ranges rng = (ranges) liter.next();

                    if (rng.name.equals(current_object.name))
                    {

                        ranges_found++;

                    }

                }


                current_object.dynamic_object_ranges = new ranges[ranges_found];


                int val = 0;


                liter = dynamic_object_ranges_local_facts.iterator();
                while(liter.hasNext())
                {
                    ranges rng = (ranges) liter.next();



                    if (rng.name.equals(current_object.name))
                    {
                        current_object.dynamic_object_ranges[val] = rng;
                        current_object.local_config += rng.local_config ;

                        val++;

                    }

                }
            
            
                 return current_object;
            
            } catch (Exception e)
            {
              
                log_handler.log_in_gui("(RDO) Error: " + e.getLocalizedMessage(), "39040", json_response);
                return null;
            }
            
           
                
        }

        public general_network_object read_access_role(String json_response)
        {
         try
            {
            


                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.json = json_response;  

                Object tmp =  identity_awareness_local_facts.get(current_object.name);

            if (tmp == null)
            {
                
                current_object.identity_count = 0;      
                
            }
            else
            {
                int count = (Integer) tmp;
                current_object.identity_count = count;
               
            }
            
            
            return current_object;
            
            
            
         }
         catch (Exception e)
         {
  
                
                log_handler.log_in_gui("(RAR) Error: " + e.getLocalizedMessage(), "421046", json_response);
                return null;
         }
                 
        
    }
     
    public general_network_object read_data_center_object(String json_response)
        {
         try
         {

            general_network_object current_object = new general_network_object();     
            Object rss_parser = new JSONParser().parse(json_response);     
            JSONObject js_current_object = (JSONObject) rss_parser; 

            current_object.uid = (String) js_current_object.get("uid");
            current_object.name = (String) js_current_object.get("name");
            current_object.type = (String) js_current_object.get("type");
            current_object.json = json_response;  

            Object tmp =  identity_awareness_local_facts.get(current_object.name);

            if (tmp == null)
            {

                  current_object.identity_count = 0;         
            }
            else
            {
                int count = (Integer) tmp;
                current_object.identity_count = count;

            }


                 return current_object;


            
         }
         catch (Exception e)
         {
  
                System.out.println("(RDCO) Error: " + e.getMessage());
                log_handler.log_in_gui("(RDCO) Error: " + e.getLocalizedMessage(), "437303", json_response);
                return null;
         }
                 
        
    }     
        
     
          
    public general_network_object read_domain_object(String json_response)
        {
           
            
            
            try
            {
            
                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");         
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           

                boolean subdomain = (boolean) js_current_object.get("is-sub-domain");


                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");

                if (group_array != null)
                {
                    Iterator i = group_array.iterator();



                    int array_size = group_array.size();

                    current_object.member_of = new String[array_size];
                    int val = 0;


                    while (i.hasNext()) 
                    {

                        JSONObject group = (JSONObject) i.next();

                        current_object.member_of[val] =  (String) group.get("name");

                        val++;

                    }
                }


            // sprawdz czy obiekt istnieje w lokalnej konfiguracji
            
            
            Iterator liter = domain_objects_ranges_local_facts.iterator();
            int ranges_found = 0;
            
            while(liter.hasNext())
            {
                
                ranges rng = (ranges) liter.next();
              
                    // jezeli jest subdomena to interesuje nas tylko jedna wpis
                   
                if (current_object.name.equals("."+rng.name))
                {
                //    System.out.println(current_object.name + " subdomain " + rng.name + " " +rng.range_start);
                    ranges_found++;

                }

            }
            

                current_object.domain_object_ranges = new ranges[ranges_found];


                int val = 0;


                liter = domain_objects_ranges_local_facts.iterator();
                while(liter.hasNext())
                {
                    ranges rng = (ranges) liter.next();


                        if (current_object.name.equals("."+ rng.name))
                        {


                            current_object.domain_object_ranges[val] = rng;
                            current_object.local_config += rng.local_config ;

                            val++;
                        }

                }


                 return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RDO) Error: " + e.getLocalizedMessage(), "235619" , json_response);
                return null;
                
            }
            
           
                
        }

            
        
          
    public general_network_object read_updatable_object(String json_response)
        {
            // read network settings
            
            
            try
            {
            
                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           

                // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");

                if (group_array != null)
                {
                    Iterator i = group_array.iterator();
                    int array_size = group_array.size();

                    current_object.member_of = new String[array_size];
                    int val = 0;


                    while (i.hasNext()) 
                    {

                        JSONObject group = (JSONObject) i.next();

                        current_object.member_of[val] =  (String) group.get("name");

                        val++;

                    }
                }

            
            // sprawdz czy obiekt istnieje w lokalnej konfiguracji


                Iterator liter = updatable_object_ranges_local_facts.iterator();
                int ranges_found = 0;

                while(liter.hasNext())
                {

                    ranges rng = (ranges) liter.next();


                    if (rng.name.equals(current_object.name))
                    {

                        ranges_found++;

                    }

                }

           
            
              current_object.updatable_object_ranges = new ranges[ranges_found];
            

                int val = 0;

                liter = updatable_object_ranges_local_facts.iterator();
                while(liter.hasNext())
                {
                    ranges rng = (ranges) liter.next();



                    if (rng.name.equals(current_object.name))
                    {
                        current_object.updatable_object_ranges[val] = rng;

                        current_object.local_config += rng.local_config ;





                        val++;

                    }

                }

            
                 return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RUO) Error: " + e.getLocalizedMessage(), "421046" , json_response);
                return null;
                
            }
            
           
                
        }

         
          

       
       
       
       public general_network_object read_network(String json_response)
        {
            // read network settings
            
            
            try
            {

                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.network = (String) js_current_object.get("subnet4");
                current_object.network_mask = (String) js_current_object.get("subnet-mask");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           
          
                // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");


                }

               
                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;

           
                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();

                    current_object.member_of[val] =  (String) group.get("name");

                    val++;

                }

            
                return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RN) Error: " + e.getLocalizedMessage(), "35812", json_response);
                return null;
            }
            
           
                
        }

       
          
       public general_network_object read_wildcard(String json_response)
        {
            // read wildcard settings
            
            
            try
            {
            
                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.network = (String) js_current_object.get("ipv4-address");
                current_object.ipv4_mask_wildcard = (String) js_current_object.get("ipv4-mask-wildcard");
                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           
          

                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;

           
                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();

                    current_object.member_of[val] =  (String) group.get("name");

                    val++;

                }

            
                return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RW) Error: " + e.getLocalizedMessage(), "50429", json_response);
                return null;
            }
            
           
                
        }

       public general_network_object read_checkpoint_host(String json_response)
        {
            // read network settings
            
            
            try
            {
            
                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.address = (String) js_current_object.get("ipv4-address");

                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           
          

                // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");




                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;


                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();
                    current_object.member_of[val] =  (String) group.get("name");

                    val++;

                }
            

                JSONArray interface_array = (JSONArray) js_current_object.get("interfaces");
                i = interface_array.iterator();
                array_size = interface_array.size();

                current_object.interfaces = new ckp_interface[array_size];
                val = 0;

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    current_object.interfaces[val] = new ckp_interface();


                    current_object.interfaces[val].name =  (String) ckp_interface.get("name");
                    current_object.interfaces[val].address =  (String) ckp_interface.get("subnet4");
                    val++;

                }

            
            
                return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RCPH) Error: " + e.getLocalizedMessage(), "67604", json_response);
                return null;
            }
            
           
                
        }
    
       public general_network_object read_simple_gateway(String json_response)
        {
            // read network settings
            
            
            try
            {

                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.address = (String) js_current_object.get("ipv4-address");

                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           
            
            // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 
                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");

                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;

           
            while (i.hasNext()) 
            {
                
                JSONObject group = (JSONObject) i.next();              
                current_object.member_of[val] =  (String) group.get("name");           
                val++;
                
            }
            
            
                JSONArray interface_array = (JSONArray) js_current_object.get("interfaces");
                i = interface_array.iterator();
                array_size = interface_array.size();

                current_object.interfaces = new ckp_interface[array_size];
                val = 0;

                while (i.hasNext()) 
                {

                    JSONObject ckp_interface = (JSONObject) i.next();
                    current_object.interfaces[val] = new ckp_interface();
                     current_object.interfaces[val].name =  (String) ckp_interface.get("name");
                    current_object.interfaces[val].address =  (String) ckp_interface.get("ipv4-address");
                    val++;

                }
       
                return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RSG) Error: " + e.getLocalizedMessage(), "62474", json_response);
                return null;
            }
            
           
                
        }

       
        public general_network_object read_simple_cluster(String json_response)
        {
                     
            try
            {

                general_network_object current_object = new general_network_object();     
                Object rss_parser = new JSONParser().parse(json_response);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                current_object.uid = (String) js_current_object.get("uid");
                current_object.name = (String) js_current_object.get("name");
                current_object.type = (String) js_current_object.get("type");
                current_object.address = (String) js_current_object.get("ipv4-address");

                current_object.comment = (String) js_current_object.get("comment");
                current_object.json = json_response;           
          
           
           
                // handle net if selected
                JSONObject js_current_object_nat = (JSONObject) js_current_object.get("nat-settings"); 

                if ( js_current_object_nat != null)
                {

                        current_object.nat_address = (String) js_current_object_nat.get("ipv4-address");
                        current_object.install_on =  (String) js_current_object_nat.get("install-on");
                        current_object.method =  (String) js_current_object_nat.get("method");

                }
            

                JSONArray group_array = (JSONArray) js_current_object.get("groups");
                Iterator i = group_array.iterator();
                int array_size = group_array.size();

                current_object.member_of = new String[array_size];
                int val = 0;


                while (i.hasNext()) 
                {

                    JSONObject group = (JSONObject) i.next();                
                    current_object.member_of[val] =  (String) group.get("name");                
                    val++;

                }

            JSONObject interface_object = (JSONObject) js_current_object.get("interfaces");          
            JSONArray interface_array = (JSONArray) interface_object.get("objects");
            i = interface_array.iterator();
            array_size = interface_array.size();
            
            current_object.interfaces = new ckp_interface[array_size];
            val = 0;
            
            while (i.hasNext()) 
            {
                
                JSONObject ckp_interface = (JSONObject) i.next();
                current_object.interfaces[val] = new ckp_interface();           
                current_object.interfaces[val].name =  (String) ckp_interface.get("name");
                current_object.interfaces[val].address =  (String) ckp_interface.get("ipv4-address");
                val++;
                
            }

                JSONArray cluster_members_array = (JSONArray) js_current_object.get("cluster-members");
                i = cluster_members_array.iterator();
                array_size = cluster_members_array.size();


                current_object.cluster_members = new cluster_member[array_size];
                val = 0;
           
           
                while (i.hasNext()) 
                {

                    JSONObject member = (JSONObject) i.next();
                    current_object.cluster_members[val] = new cluster_member();
                    current_object.cluster_members[val].name =  (String) member.get("name");
                    current_object.cluster_members[val].type =  "cluster-member";
                    current_object.cluster_members[val].address =  (String) member.get("ipv4-address");

                    {
                        JSONArray member_interface_array = (JSONArray) member.get("interfaces");
                        Iterator i_interface = member_interface_array.iterator();
                        int interface_array_size = member_interface_array.size();

                        current_object.cluster_members[val].interfaces = new ckp_interface[interface_array_size];
                        int val_interface = 0;

                        while (i_interface.hasNext()) 
                        {
                            JSONObject member_interface = (JSONObject) i_interface.next();

                            current_object.cluster_members[val].interfaces[val_interface] = new ckp_interface();


                            current_object.cluster_members[val].interfaces[val_interface].name = (String) member_interface.get("name");
                            current_object.cluster_members[val].interfaces[val_interface].address = (String) member_interface.get("ipv4-address");
                            val_interface++;

                        }       


                    }   

                val++;
                
            }
            
 
            return current_object;
            
            } catch (Exception e)
            {
                
                log_handler.log_in_gui("(RSC) Error: " + e.getLocalizedMessage(), "11189" , json_response);
                return null;
            }
            
           
                
        }

       
        public String find_object_in_dictionary_set(String name, String type)
        {
            Iterator iter = network_object_set.iterator();
            boolean found = false;
            
        
            
            while(iter.hasNext())
            {
                

                 general_network_object set_item = (general_network_object) iter.next();
            
                 if ((name.equals(set_item.name)) && (type.equals(set_item.type) ))
                 {
                   
                     found = true;
                     return set_item.json;
                     

                 }

            }

            if (found == false)
            {

               return null;
            }

           
            return "";
            
            
        }
             
        
      
       
       public void add_general_network_object_to_dictionary_set(general_network_object gno)
       {
           
            String name = gno.name;
            String type = gno.type;
           
           try
           {
           
                name = gno.name;
                type = gno.type;

               if(network_object_set.isEmpty())
               {
                   // if set is empty add fist element

                   network_object_set.add(gno);
                   network_object_explorer.add_network_object(gno);

               }
                else
                {

                 Iterator iter = network_object_set.iterator();
                 boolean found = false;

                 while(iter.hasNext())
                 {


                      general_network_object set_item = (general_network_object) iter.next();

                      if (name.equals(set_item.name) && type.equals(set_item.type) )
                      {

                          found = true;
                          break;

                      }

                 }

                if (found == false)
                {

                    network_object_set.add(gno);
                    network_object_explorer.add_network_object(gno);
                }

               }

           }
           catch (Exception e)
           {
               
               log_handler.log_in_gui("(AGNOTD) Error: " + e.getLocalizedMessage() + "\n", "49283" , name + " " + type);
               
           }
       }
       
       
          
       public void add_service_object_to_range_set(CheckPoint_Management_API_Rule_Processor.Object_service_range srv_object)
       {

            // add range to temporary store only when it was not visible befor 
            // we dont want to handle the same object multiple time

            // to do
            // add objects to global network dictionary

            String name = srv_object.name;
            String type = srv_object.type;

            try
            {    

            int extra_opt = srv_object.extra_options;


            if(temporary_service_range_set.isEmpty())
            {

                 temporary_service_range_set.add(srv_object);

            }
            else
            {

             Iterator iter = temporary_service_range_set.iterator();
             boolean found = false;

             while(iter.hasNext())
             {
                 
                  CheckPoint_Management_API_Rule_Processor.Object_service_range osr = (CheckPoint_Management_API_Rule_Processor.Object_service_range) iter.next();

                  if (name.equals(osr.name) && type.equals(osr.type) && extra_opt == osr.extra_options)
                  {

                      found = true;
                      break;

                  }

             }

             if (found == false)
             {

                 temporary_service_range_set.add(srv_object);

             }

            }
           }
           catch (Exception e)
           {
               
               log_handler.log_in_gui("(ASOTRS) Error: " + e.getLocalizedMessage() + "\n", "322354" , name + " " + type);
               
           }
       }
     
       
       
       public void add_network_object_to_range_set(CheckPoint_Management_API_Rule_Processor.Object_network_range net_object)
       {
           
           // add range to temporary store only when it was not visible befor 
           // we dont want to handle the same object multiple time
           
           // to do
           // add objects to global network dictionary
           
           String name = net_object.name;
           String type = net_object.type;
           
           try
           {    

                int extra_opt = net_object.extra_options;


                if(temporary_network_range_set.isEmpty())
                {

                     temporary_network_range_set.add(net_object);

                }
                else
                {

                 Iterator iter = temporary_network_range_set.iterator();

                 boolean found = false;

                while(iter.hasNext())
                {


                     Object_network_range onr = (Object_network_range) iter.next();

                     if (name.equals(onr.name) && type.equals(onr.type) && extra_opt == onr.extra_options)
                     {

                         found = true;
                         break;

                     }

                }

                if (found == false)
                {

                    temporary_network_range_set.add(net_object);

                }

            }
           }
           catch (Exception e)
           {
               
               log_handler.log_in_gui("(ANOTRS) Error: " + e.getLocalizedMessage() + "\n", "448543" , name + " " + type);
               
           }
       }
       
       
       public String check_checkpoint_object_type(String name)
       {
           
           // check if this is simple-cluster
           
               // api call
           
           try
           {

                String api_query_body = Mgmt_API_Object_get_by_name(name);
                String api_query_respond = Mgmt_API_REST_Call("show-simple-cluster" , api_query_body, name, "", "simple-cluster");  
               // general_network_object net_object = read_checkpoint_host(api_query_respond);

                Object rss_parser = new JSONParser().parse(api_query_respond);     
                JSONObject js_current_object = (JSONObject) rss_parser; 

                String type = (String) js_current_object.get("type");

                if (type != null)
                {
                    if (type.equals("simple-cluster"))
                    {


                        return type;
                    }
                }
           // check if this is simple-gateway        
                    

            api_query_body = Mgmt_API_Object_get_by_name(name);
            api_query_respond = Mgmt_API_REST_Call("show-simple-gateway" , api_query_body, name, "" , "simple-gateway");  
          // general_network_object net_object = read_checkpoint_host(api_query_respond);

            rss_parser = new JSONParser().parse(api_query_respond);     
            js_current_object = (JSONObject) rss_parser; 
            type = (String) js_current_object.get("type");

            if (type != null)
            {
                if (type.equals("simple-gateway"))
                {


                    return type;
                }
            }
           
           
           }
           catch (Exception e)
           {
               
                log_handler.log_in_gui("(CCOT) ERROR: " + e.getLocalizedMessage() + "\n", "10094", name);
                return "";  
               
               
           }
           
           return "";
           
       }
       
   public long ipToLong(String ipAddress)
    {
        
            String[] ipAddressInArray = ipAddress.split("\\.");

            long result = 0;
            for (int i = 0; i < ipAddressInArray.length; i++) 
            {

                int power = 3 - i;
                int ip = Integer.parseInt(ipAddressInArray[i]);
                result += ip * Math.pow(256, power);

            }

    return result;
  }
   

      
  public String CalculateBroadCastAddress(String currentIP, String ipNetMask)
{
    try
    {
        
        String[] strCurrentIP = currentIP.split("\\.");
        String[] strIPNetMask = ipNetMask.split("\\.");

        String[] arBroadCast = new String[4];

        for (int i = 0; i < 4; i++)
        {
            
            int nrBCOct = Integer.parseInt(strCurrentIP[i]) | (Integer.parseInt(strIPNetMask[i]) ^ 255);

            arBroadCast[i] = new String();
            arBroadCast[i] = String.valueOf(nrBCOct);



        }
        return (arBroadCast[0] + "." + arBroadCast[1] + "." + arBroadCast[2] + "." + arBroadCast[3]);

    }
    catch (Exception e)
    {
        
        log_handler.log_in_gui("(CBA) ERROR: " + e.getLocalizedMessage() + "\n", "849783", "");
        return null;
        
    }
}
   // 255 upper range
        
        public Object_service_range calculate_service_range(Object_service_range gsr)
        {
            try
            {
                if ((gsr.protocol == null) || (gsr.protocol.equals("")))
                {
                    
                    gsr.protocol = "Any";
          
                }
                if ((gsr.icmptype == null) || (gsr.icmptype.equals("")))
                {
                    gsr.icmptype = "Any";
                    
                    
                }
                if ((gsr.app_id == null) || (gsr.app_id.equals("")))
                {
                    
                    gsr.app_id = "Any";
         
                }
                
                // czasami pojawia sie zapis >0 
                if ((gsr.start.equals(">0")) ||  (gsr.start.equals(" ")))
                {
                    gsr.start = "Any";
                    gsr.end = "Any";
                    
                }
                if ((gsr.end.equals(">0")) || (gsr.end.equals(" ")))
                {
                    gsr.start = "Any";
                    gsr.end = "Any";
                    
                }

                if (!gsr.start.equals(""))
                {
                      if ((gsr.start.equals("Any")) || (gsr.end.equals("ANY") ))
                      {
                          gsr.c_range_start = -1;
                      }
                      else
                      {

                         gsr.c_range_start = Long.parseLong(gsr.start); 

                      }
                }
                
                if (!gsr.end.equals(""))
                {
                      if  (gsr.end.equals("Any") || (gsr.end.equals("ANY") ))
                      {
                          gsr.c_range_stop = -1;
                      }
                      else
                      {

                          gsr.c_range_stop = Long.parseLong(gsr.end);

                      }
                    
                   
                }
                
                if (!gsr.protocol.equals(""))
                {
                      if  (gsr.protocol.equals("Any") || (gsr.protocol.equals("ANY") ))
                      {
                          gsr.c_protocol = -1;
                      }
                      else
                      {

                         gsr.c_protocol = Long.parseLong(gsr.protocol); 

                      }
                }
                
                if (!gsr.icmptype.equals(""))
                {
                      if  (gsr.icmptype.equals("Any") || (gsr.icmptype.equals("ANY") ))
                      {
                          gsr.c_icmp_type = -1;
                      }
                      else
                      {

                         gsr.c_icmp_type = Long.parseLong(gsr.icmptype); 

                      }
                }
                
                
                if (!gsr.app_id.equals(""))
                {
                      if  (gsr.app_id.equals("Any") || (gsr.app_id.equals("ANY") ))
                      {
                          gsr.c_app_id = -1;
                      }
                      else
                      {

                         gsr.c_app_id = Long.parseLong(gsr.app_id); 

                      }
                }
                
                
          /*      
                if (!gsr.protocol.equals(""))
                {
                    gsr.c_protocol = Long.parseLong(gsr.protocol);
                }
                
                if (gsr.icmptype == null)
                {
                    
                     gsr.c_icmp_type = -1;
                    
                }
                else
                {
                    if (!gsr.icmptype.equals(""))
                    {
                        gsr.c_icmp_type = Long.parseLong(gsr.icmptype);
                    }
                    else
                    {
                        
                        gsr.c_icmp_type = -1;
                        
                    }
                    
                }


                if (gsr.app_id != null)
                {
                   
               
                
                    if (!gsr.app_id.equals(""))
                    {
                        gsr.c_app_id = Long.parseLong(gsr.app_id);
                    }
                    else
                    {
                        gsr.c_app_id = -1;
                    }
                    
                    
                 }
                else
                {
                     gsr.c_app_id = -1;
                    
                }
*/
               // System.out.println(gsr.name + " " + gsr.protocol + " " + gsr.c_protocol + " " + gsr.c_range_start + " " + gsr.c_range_stop + " " + gsr.app_id  + " " + gsr.c_app_id);
                
            }
            catch (Exception e)
            {
               
                System.out.println(" |" + gsr.name + "| Proto|" + gsr.protocol + "|" + gsr.c_protocol + "| Range |" + gsr.start + "|" + gsr.end + "|" + gsr.c_range_start + "|" + gsr.c_range_stop + "| APP |" + gsr.app_id  + "|" + gsr.c_app_id + "| icmp |" + gsr.icmptype  + "|" + gsr.c_icmp_type + "|");
                log_handler.log_in_gui("(CSR) ERROR: " + gsr.name + " " + e.getLocalizedMessage() + "\n", "886102", gsr.name);
                
                return gsr;  
               
            }
            
            return gsr;
        }
  
   
       public Object_network_range calculate_network_range(Object_network_range gnr)
       {
           
           try
           {
               
                      
            if ((gnr.type.equals("host")) || (gnr.type.equals("CpmiGatewayPlain")) || (gnr.type.equals("simple-gateway")) || (gnr.type.equals("checkpoint-host"))  || (gnr.type.equals("CpmiLogicalServer")))
            {
       
                gnr.c_range_start = ipToLong(gnr.address);
                gnr.c_range_stop = ipToLong(gnr.address);
            
               
                return gnr;
                
            }
            if ((gnr.type.equals("network")) ||   (gnr.type.equals("CpmiAnyObject")) )
            {
                
                gnr.c_range_start = ipToLong(gnr.network);
                gnr.c_range_stop = ipToLong(CalculateBroadCastAddress(gnr.network, gnr.network_subnet));
                
             
                return gnr;
                
            }
            
            if ((gnr.type.equals("address-range")) ||   (gnr.type.equals("dns-domain"))  ||   (gnr.type.equals("updatable-object")) )
            {
              //  System.out.println("s " + gno.range_start + " e " + gno.range_end);
                
                if (((gnr.range_start != null) && (gnr.range_end != null)) )
                {

                    if (!gnr.range_start.equals(""))
                    {
                        gnr.c_range_start = ipToLong(gnr.range_start);
                        gnr.c_range_stop = ipToLong(gnr.range_end);        
                                
                    }

                    return gnr;
                }
            }
            
            if (gnr.type.equals("dynamic-object")) 
            {
                //System.out.println(gno.range_start + " X " + gno.range_end); 
                
                if ((gnr.range_start != null) && (gnr.range_end != null))
                {
                    
                    gnr.c_range_start = ipToLong(gnr.range_start);
                    gnr.c_range_stop = ipToLong(gnr.range_end);
                    
                     return gnr;     
                }
               
               
            }
            
            if (gnr.type.equals("wildcard")) 
            {
                
                
                if ((gnr.range_start != null) && (gnr.range_end != null))
                {
                    
                    
                     gnr.c_wildcard_subnet = ipToLong(gnr.network);
                     gnr.c_wildcard_subnet = ipToLong(gnr.network_subnet);
                    
                     return gnr;     
                }
               
               
            }
            
            
            if (gnr.type.equals("security-zone"))
            {
                
                gnr.c_range_start = ipToLong(gnr.network);
                gnr.c_range_stop = ipToLong(CalculateBroadCastAddress(gnr.network, gnr.network_subnet));
                
             
                return gnr;
                
            }
            
            if (gnr.type.equals("access-role"))
            {
                return gnr;
                
            }
            
   
                System.out.println(gnr.type);
                return gnr;
           }
           catch (Exception e)
           {
               
                log_handler.log_in_gui("(CNR) ERROR: " + gnr.name + " " + e.getLocalizedMessage() + "\n", "745580", gnr.name);
                return gnr;  
               
           }
           
          
       }
       
       
       public void calculate_object(String name, String uid, String type, int extra_option, String column , String rule_number , boolean  supress_view)
       {
           
           try
           {
           
   
               if (name == null)
               {
                
                   throw new NullPointerException("name");
                   
               }
               
               if (type == null)
               {
                   
                    throw new NullPointerException("type");
                   
               }
               
           // to do cache handling 
           // no to call every object multiple time
           
                
           // check object type from rule and call mgmt for details
           // each type threated differently
           
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE HOST
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           
            if (type.equals("host"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-host" , api_query_body, name, uid, type);  
               general_network_object net_object = read_host(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);
               
               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);
               
               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = net_object.type;
                   net_range_object_nat.extra_options = extra_option;
                  
                   
                   
                   
                   if ((net_object.install_on.equals("All"))  || (net_object.install_on.equals(FIREWALL_to_analyze)))
                   {
                       if ( net_object.method.equals("Static") || net_object.method.equals("static"))
                       {
                            net_range_object_nat = calculate_network_range(net_range_object_nat);
                            add_network_object_to_range_set(net_range_object_nat);     
                            
                       }    
                     

                    }
                   else
                   {
                       
                       log_handler.log_in_gui(" Warning: Rule "+ rule_number  +". NAT on " + net_object.name + " not on Policy Target \n");
                       
                   }
                   
       //current_object.install_on            

                   // temporary_source_range_set.add(net_range_object_nat);

               }
                    
                    

                int interface_size = net_object.interfaces.length;

                for (int i = 0; i < interface_size ; i++)
                {
                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                    net_range_object_interface = temp.new Object_network_range();

                    net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name;
                    net_range_object_interface.address = net_object.interfaces[i].address;
                    net_range_object_interface.type = net_object.type;
                    net_range_object_interface.extra_options = extra_option;

                    net_range_object_interface = calculate_network_range(net_range_object_interface);
                    add_network_object_to_range_set(net_range_object_interface);



                }
                    
                 return;
                    
            }
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE CpmiGatewayPlain
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////   
            

            if (type.equals("CpmiGatewayPlain"))
            {



                // api call
               String api_query_body = Mgmt_API_Object_get_by_by_id(uid);
               String api_query_respond = Mgmt_API_REST_Call("show-generic-object" , api_query_body, name, uid, type);  
               general_network_object net_object = read_interoperable_device(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);



               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;



              // fill object details
               net_range_object = temp.new Object_network_range();
               //net_range_object = new CheckPoint_Management_API_Rule_Processor.Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;
               
               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                //   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                //  net_range_object_nat = temp.new Object_network_range();
                //   net_range_object_nat.name = net_object.name +" - NAT";
                //   net_range_object_nat.address = net_object.nat_address;                     
                //   net_range_object_nat.type = net_object.type;
                //   net_range_object_nat.extra_options = extra_option;

                //   net_range_object = calculate_network_range(net_range_object);
                //   add_network_object_to_range_set(net_range_object_nat);
               

               }

                int interface_size = net_object.interfaces.length;

                for (int i = 0; i < interface_size ; i++)
                {


                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                    net_range_object_interface = temp.new Object_network_range();

                    net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name;
                    net_range_object_interface.address = net_object.interfaces[i].address;
                    net_range_object_interface.type = net_object.type;
                    net_range_object_interface.extra_options = extra_option;

                    net_range_object = calculate_network_range(net_range_object);
                    add_network_object_to_range_set(net_range_object_interface);

                }


               return;
            }
            
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE CpmiOseDevice
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////   
            

            if (type.equals("CpmiOseDevice"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_by_id(uid);
               String api_query_respond = Mgmt_API_REST_Call("show-generic-object" , api_query_body, name, uid, type);  
               general_network_object net_object = read_ose_device(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);

               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = net_object.type;
                   net_range_object_nat.extra_options = extra_option;

                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object_nat);
                
               }

               int interface_size = net_object.interfaces.length;

               for (int i = 0; i < interface_size ; i++)
               {


                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                   net_range_object_interface = temp.new Object_network_range();

                   net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name;
                   net_range_object_interface.address = net_object.interfaces[i].address;
                   net_range_object_interface.type = net_object.type;
                   net_range_object_interface.extra_options = extra_option;

                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object_interface);



               }

               return;

            }


           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE CpmiOseDevice
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////   
            

            if (type.equals("network"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);                  
               String api_query_respond = Mgmt_API_REST_Call("show-network" , api_query_body, name, uid, type);                      
               general_network_object net_object = read_network(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);
               
               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;


               // fill network details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.network = net_object.network;
               net_range_object.network_subnet = net_object.network_mask;
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);

               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;
                   net_range_object_nat.network = net_object.nat_address;
                   net_range_object_nat.network_subnet=  "255.255.255.255";
                   net_range_object_nat.type = "host" ;// nie da sie uzyc innego obiektu net_object.type;
                   net_range_object_nat.extra_options = extra_option;
                   
                //   net_range_object_nat = calculate_network_range(net_range_object_nat);
                //   add_network_object_to_range_set(net_range_object_nat);


                    if ((net_object.install_on.equals("All"))  || (net_object.install_on.equals(FIREWALL_to_analyze)))
                    {
                        if ( net_object.method.equals("Static") || net_object.method.equals("static"))
                        {
                             net_range_object_nat = calculate_network_range(net_range_object_nat);
                             add_network_object_to_range_set(net_range_object_nat);     

                        }    


                     }
                    else
                    {

                        log_handler.log_in_gui(" Warning: Rule "+ rule_number  +". NAT on " + net_object.name + " not on Policy Target \n");

                    }
                }

               return;

            }

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE address-range
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

            if (type.equals("address-range"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-address-range" , api_query_body, name, uid, type);  
               general_network_object net_object = read_range(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.range_start = net_object.range_start;                 
               net_range_object.range_end = net_object.range_end;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = "host";
                   net_range_object_nat.extra_options = extra_option;
         
                   
                  // net_range_object_nat = calculate_network_range(net_range_object_nat);
                  // add_network_object_to_range_set(net_range_object_nat);
                   // temporary_source_range_set.add(net_range_object_nat);
                   
                   if ((net_object.install_on.equals("All"))  || (net_object.install_on.equals(FIREWALL_to_analyze)))
                   {
                       if ( net_object.method.equals("Static") || net_object.method.equals("static"))
                       {
                            net_range_object_nat = calculate_network_range(net_range_object_nat);
                            add_network_object_to_range_set(net_range_object_nat);     
                            
                       }    
                     

                    }
                   else
                   {
                       
                       log_handler.log_in_gui(" Warning: Rule "+ rule_number  +". NAT on " + net_object.name + " not on Policy Target \n");
                       
                   }
                   
       //current_object.install_on            

                   // temporary_source_range_set.add(net_range_object_nat);

               
                    
               }

               return;

            }

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE wildcard
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  



            if (type.equals("wildcard"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);                  
               String api_query_respond = Mgmt_API_REST_Call("show-wildcard" , api_query_body, name, uid, type);                      
               general_network_object net_object = read_wildcard(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);



               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;


               // fill network details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.network = net_object.network;
               net_range_object.network_subnet = net_object.ipv4_mask_wildcard;
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               return;

            }

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE ANY CpmiAnyObject  network
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

            if (type.equals("CpmiAnyObject") && column.equals("network")) 
            {


               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // object ANY just fill standard values

               net_range_object = temp.new Object_network_range();

               net_range_object.name = "Any";
               net_range_object.network = "0.0.0.0";
               net_range_object.network_subnet = "0.0.0.0";
               net_range_object.type = "CpmiAnyObject";
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);



               return;

            }
                 
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE data-center-object
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
   

            if (type.equals("data-center-object")) 
            {


                String api_query_body = Mgmt_API_Object_get_by_name(uid);
               String api_query_respond = Mgmt_API_REST_Call("show-data-center-object" , api_query_body, name, uid, type);  
               general_network_object net_object = read_data_center_object(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);




               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // object ANY just fill standard values

               net_range_object = temp.new Object_network_range();

               net_range_object.name = net_object.name;
               net_range_object.network = "";
               net_range_object.network_subnet = "";
               net_range_object.type = "data-center-object";
               net_range_object.object_count = net_object.identity_count;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               return;

            }

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE access-role
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
   
                 

            if (type.equals("access-role")) 
            {
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-access-role" , api_query_body, name, uid, type);  
               general_network_object net_object = read_access_role(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // object ANY just fill standard values

               net_range_object = temp.new Object_network_range();

               net_range_object.name = net_object.name;
               net_range_object.network = "";
               net_range_object.network_subnet = "";
               net_range_object.type = "access-role";
               net_range_object.object_count = net_object.identity_count;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               return;

            }
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE security-zone
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
   


            if (type.equals("security-zone")) 
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);                  
               String api_query_respond = Mgmt_API_REST_Call("show-security-zone" , api_query_body, name, uid, type);                      
               general_network_object net_object = read_security_zone(api_query_respond, rule_number);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;


                for (int k = 0 ; k < net_object.interfaces.length; k ++)
                {

                    if (net_object.interfaces[k] == null)
                    {

                        log_handler.log_in_gui(" Warning: Rule "+ rule_number  + ". Security zone '" + net_object.name + "' is not configured on " + FIREWALL_to_analyze + ". Object ingored.\n" , "" , "");
                    }
                    else
                    {
                        net_range_object = temp.new Object_network_range();
                        net_range_object.name = net_object.name + "." + net_object.interfaces[k].name;                       
                        net_range_object.network = "0.0.0.0";
                        net_range_object.network_subnet = "0.0.0.0";
                        net_range_object.type = "security-zone";
                        net_range_object.ckp_interface =  net_object.interfaces[k].name;
                        net_range_object.extra_options = extra_option;

                        net_range_object = calculate_network_range(net_range_object);
                        add_network_object_to_range_set(net_range_object);

                    }
                }

               return;
            }

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE group
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
   

            
                          
            if (type.equals("group")) 
            {

               // api call               
               String api_query_body = Mgmt_API_Object_get_by_name(name);         
               String api_query_respond = Mgmt_API_REST_Call("show-group" , api_query_body, name, uid, type);                         
               general_network_object net_object = read_group(api_query_respond);


               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               // read group members
               int members_count = net_object.members.length;
               for (int member = 0 ; member < members_count; member++)
               {
                   // check objects nested in groups
                   calculate_object(net_object.members[member].name, net_object.members[member].uid, net_object.members[member].type, extra_option, "network" , rule_number, false);


               }

               return;
            }      

           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE service-group
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

            if (type.equals("service-group")) 
            {

               // api call               
               String api_query_body = Mgmt_API_Object_get_by_name(name);         
               String api_query_respond = Mgmt_API_REST_Call("show-service-group" , api_query_body, name, uid, type);                         
               general_network_object net_object = read_group(api_query_respond);


               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);



               // read group members
               int members_count = net_object.members.length;
               for (int member = 0 ; member < members_count; member++)
               {
                   // check objects nested in groups
                   calculate_object(net_object.members[member].name, net_object.members[member].uid, net_object.members[member].type, extra_option, "service" , rule_number , false);


               }

               return;
            }      
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE group-with-exclusion
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


            if (type.equals("group-with-exclusion")) 
            {

               // api call               
               String api_query_body = Mgmt_API_Object_get_by_name(name);         
               String api_query_respond = Mgmt_API_REST_Call("show-group-with-exclusion" , api_query_body, name, uid, type);                         
               general_network_object net_object = read_group_with_exclusion(api_query_respond);


               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               calculate_object(net_object.include_group, ""  ,  "group", 0, "network", rule_number,  false);
               calculate_object(net_object.exclude_group, ""  , "group", 1, "network", rule_number,  false);

               return;

            } 
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE checkpoint-host
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

            if (type.equals("checkpoint-host"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-checkpoint-host" , api_query_body, name, uid, type);  
               general_network_object net_object = read_checkpoint_host(api_query_respond);

               //  add to global dictionary
               add_general_network_object_to_dictionary_set(net_object);



               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = net_object.type;
                   net_range_object_nat.extra_options = extra_option;

                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object_nat);
                   // temporary_source_range_set.add(net_range_object_nat);

               }


               int interface_size = net_object.interfaces.length;

               for (int i = 0; i < interface_size ; i++)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                   net_range_object_interface = temp.new Object_network_range();

                   net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name;
                   net_range_object_interface.address = net_object.interfaces[i].address;
                   net_range_object_interface.type = net_object.type;
                   net_range_object_interface.extra_options = extra_option;

                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object_interface);



               }



               return;

            }
 
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE simple-gateway
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


            if (type.equals("simple-gateway"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-simple-gateway" , api_query_body, name, uid, type);  
               general_network_object net_object = read_simple_gateway(api_query_respond);

               //  add to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;


               if (extra_option != 2)
               {
                   // 2 nie dodawaj do tablicy range

                        net_range_object = calculate_network_range(net_range_object);
                        add_network_object_to_range_set(net_range_object);

               }

               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = net_object.type;
                   net_range_object_nat.extra_options = extra_option;

                   if (extra_option != 2)
                   {
                       // 2 nie dodawaj do tablicy range
                       
                       net_range_object = calculate_network_range(net_range_object);
                       add_network_object_to_range_set(net_range_object_nat);
                       // temporary_source_range_set.add(net_range_object_nat);

                   }                    }


               int interface_size = net_object.interfaces.length;

               for (int i = 0; i < interface_size ; i++)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                   net_range_object_interface = temp.new Object_network_range();

                   net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name;
                   net_range_object_interface.address = net_object.interfaces[i].address;
                   net_range_object_interface.type = net_object.type;
                   net_range_object_interface.extra_options = extra_option;

                  if (extra_option != 2)
                  {
                   // 2 nie dodawaj do tablicy range
                       net_range_object = calculate_network_range(net_range_object);
                       add_network_object_to_range_set(net_range_object_interface);

                  }


               }
    
               return;

            }
           
                 
    
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE simple-cluster
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  



            if (type.equals("simple-cluster"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-simple-cluster" , api_query_body, name, uid, type);  
               general_network_object net_object = read_simple_cluster(api_query_respond);

               //  add to global dictionary
               add_general_network_object_to_dictionary_set(net_object);



               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.address = net_object.address;                 
               net_range_object.type = net_object.type;
               net_range_object.extra_options = extra_option;


               if (extra_option != 2)
               {
                   // 2 nie dodawaj do tablicy range
                    net_range_object = calculate_network_range(net_range_object);
                    add_network_object_to_range_set(net_range_object);

               }
               // if object have nat option selected 
               // create extra object for nat 
               if (net_object.nat_address != null)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_nat;
                   net_range_object_nat = temp.new Object_network_range();
                   net_range_object_nat.name = net_object.name +" - NAT";
                   net_range_object_nat.address = net_object.nat_address;                     
                   net_range_object_nat.type = net_object.type;
                   net_range_object_nat.extra_options = extra_option;


                    if (extra_option != 2)
                    {
                     // 2 nie dodawaj do tablicy range
                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object_nat);
                   // temporary_source_range_set.add(net_range_object_nat);
                     }
               }


               int interface_size = net_object.interfaces.length;

               for (int i = 0; i < interface_size ; i++)
               {
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                   net_range_object_interface = temp.new Object_network_range();

                   net_range_object_interface.name = net_object.name + "." + net_object.interfaces[i].name + ".VIP";
                   net_range_object_interface.address = net_object.interfaces[i].address;
                   net_range_object_interface.type = net_object.type;
                   net_range_object_interface.extra_options = extra_option;

                   if (net_range_object_interface.address.equals(""))
                   {
                       // interfejs bez adresu wirtualnego nie dodajemy do rangwo

                   }

                   else
                   {

                          if (extra_option != 2)
                           {
                            // 2 nie dodawaj do tablicy range
                                    net_range_object = calculate_network_range(net_range_object);
                                    add_network_object_to_range_set(net_range_object_interface);

                           }
                   }


               }

               int cluster_member_count = net_object.cluster_members.length;

                for (int i = 0; i < cluster_member_count ; i++)
                {

                    // po wszystkich czlonkach

                    int interface_count = net_object.cluster_members[i].interfaces.length;

                    for ( int k = 0 ; k < interface_count ; k++)
                    {

                        // po wszystkich interfejsach 

                       CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object_interface;
                       net_range_object_interface = temp.new Object_network_range();

                       net_range_object_interface.name = net_object.name + "." + net_object.cluster_members[i].interfaces[k].name + "." + net_object.cluster_members[i].name;
                       net_range_object_interface.address = net_object.cluster_members[i].interfaces[k].address;
                       net_range_object_interface.type = net_object.type;
                       net_range_object_interface.extra_options = extra_option;

                       if (extra_option != 2)
                       {
                           // 2 nie dodawaj do tablicy range
                           net_range_object = calculate_network_range(net_range_object);
                           add_network_object_to_range_set(net_range_object_interface);

                       } 
                    }




                }


               return;
            }

            
                
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE dynamic-object
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


            if (type.equals("dynamic-object"))
            {

                // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-dynamic-object" , api_query_body, name, uid, type);  
               general_network_object net_object = read_dynamic_object(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               for (int i = 0 ; i < net_object.dynamic_object_ranges.length ; i++)
               {

                   CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
                   net_range_object = temp.new Object_network_range();
                   net_range_object.name = net_object.name + "." +net_object.dynamic_object_ranges[i].number;
                   net_range_object.range_start = net_object.dynamic_object_ranges[i].range_start;                 
                   net_range_object.range_end = net_object.dynamic_object_ranges[i].range_end;                 
                   net_range_object.type = net_object.type;
                   net_range_object.extra_options = extra_option;
                   net_range_object.object_count = net_object.dynamic_object_ranges.length;

                   //net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object);



                   if (i == 0)
                   {
                       net_range_object.suppres_view = false;
                   //     System.out.println(net_range_object.name + " "  + net_range_object.object_count);
                   }
                   else
                   {

                       net_range_object.suppres_view = true;
                   //     System.out.println("suppr " + net_range_object.name + " "  + net_range_object.object_count);
                   }



               }

                if (net_object.dynamic_object_ranges.length == 0)
                {

                    log_handler.log_in_gui("Warning: Rule " + rule_number  + ". Dynamic Object '" + net_object.name + "' not foud on " + FIREWALL_to_analyze  + "' Ignoring object \n" , "", "");

                    CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

                // fill object details
                    net_range_object = temp.new Object_network_range();
                    net_range_object.name = net_object.name + "." + "0";
                    net_range_object.range_start = "";                 
                    net_range_object.range_end = "";   
                    net_range_object.object_count = 0;
                    net_range_object.type = net_object.type;
                    net_range_object.extra_options = extra_option;

                    //net_range_object = calculate_network_range(net_range_object);
                    //add_network_object_to_range_set(net_range_object);

                }



               return;
            }
                    
                   
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE dns-domain
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

         

            if (type.equals("dns-domain"))
            {

                // api call
                String api_query_body = Mgmt_API_Object_get_by_name(name);
                String api_query_respond = Mgmt_API_REST_Call("show-dns-domain" , api_query_body, name, uid, type);  
                general_network_object net_object = read_domain_object(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               for (int i = 0 ; i < net_object.domain_object_ranges.length ; i++)
               {

                   CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                   CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // fill object details
                   net_range_object = temp.new Object_network_range();
                   net_range_object.name = net_object.name + "." + i;    // + "." + net_object.domain_object_ranges[i].number;
                   net_range_object.range_start = net_object.domain_object_ranges[i].range_start;                 
                   net_range_object.range_end = net_object.domain_object_ranges[i].range_end;                 
                   net_range_object.object_count = net_object.domain_object_ranges.length;
                   net_range_object.type = net_object.type;
                   net_range_object.extra_options = extra_option;


                   if (i == 0)
                   {
                       net_range_object.suppres_view = false;
                  
                   }
                   else
                   {

                       net_range_object.suppres_view = true;
               
                   }

                   net_range_object = calculate_network_range(net_range_object);
                   add_network_object_to_range_set(net_range_object);




                }

                if (net_object.domain_object_ranges.length == 0)
                {

                    log_handler.log_in_gui(" Warning: Rule " + rule_number  + ". Domain Object '" + net_object.name + "' not foud on " + FIREWALL_to_analyze  + "' Ignoring object \n" , "", "");

                    CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

                // fill object details
                    net_range_object = temp.new Object_network_range();
                    net_range_object.name = net_object.name;
                    net_range_object.range_start = "";                 
                    net_range_object.range_end = "";   
                    net_range_object.object_count = 0;
                    net_range_object.type = net_object.type;
                    net_range_object.extra_options = extra_option;

                    net_range_object.c_range_start = 0;                 
                    net_range_object.c_range_stop = 0;   
                    
                  //  net_range_object = calculate_network_range(net_range_object);
                    add_network_object_to_range_set(net_range_object);

                }




                return;
             }
        
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE updatable-object
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


            if (type.equals("updatable-object"))
            {

                 // api call
                String api_query_body = Mgmt_API_Object_get_by_name(name);
                String api_query_respond = Mgmt_API_REST_Call("show-updatable-object" , api_query_body, name, uid, type);  
                general_network_object net_object = read_updatable_object(api_query_respond);

                //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

                for (int i = 0 ; i < net_object.updatable_object_ranges.length ; i++)
                {

                    CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

                // fill object details
                    net_range_object = temp.new Object_network_range();
                    net_range_object.name = net_object.name + "." +net_object.updatable_object_ranges[i].number;
                    net_range_object.range_start = net_object.updatable_object_ranges[i].range_start;                 
                    net_range_object.range_end = net_object.updatable_object_ranges[i].range_end;   
                    net_range_object.object_count = net_object.updatable_object_ranges.length;
                    net_range_object.type = net_object.type;
                    net_range_object.extra_options = extra_option;



                    if (i == 0)
                    {
                        net_range_object.suppres_view = false;
                    //     System.out.println(net_range_object.name + " "  + net_range_object.object_count);
                    }
                    else
                    {

                        net_range_object.suppres_view = true;
                    //     System.out.println("suppr " + net_range_object.name + " "  + net_range_object.object_count);
                    }

                    net_range_object = calculate_network_range(net_range_object);
                    add_network_object_to_range_set(net_range_object);




                }





                if (net_object.updatable_object_ranges.length == 0)
                {

                    log_handler.log_in_gui(" Warning: Rule " + rule_number  + ". Updatable Object '" + net_object.name + "' not foud on " + FIREWALL_to_analyze  + "' Ignoring object \n" , "", "");

                    CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                    CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

                // fill object details
                    net_range_object = temp.new Object_network_range();
                    net_range_object.name = net_object.name + "." + "0";
                    net_range_object.range_start = "";                 
                    net_range_object.range_end = "";   
                    net_range_object.object_count = 0;
                    net_range_object.type = net_object.type;
                    net_range_object.extra_options = extra_option;

                    net_range_object = calculate_network_range(net_range_object);
                    add_network_object_to_range_set(net_range_object);

                }

                return;

            }
            
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE access-role
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
   
                 

            if (type.equals("access-role")) 
            {
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-access-role" , api_query_body, name, uid, type);  
               general_network_object net_object = read_access_role(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // object ANY just fill standard values

               net_range_object = temp.new Object_network_range();

               net_range_object.name = net_object.name;
               net_range_object.network = "";
               net_range_object.network_subnet = "";
               net_range_object.type = "access-role";
               net_range_object.object_count = net_object.identity_count;
               net_range_object.extra_options = extra_option;

               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               return;

            }
            

             //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE logical server
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


             if (type.equals("CpmiLogicalServer")) 
             {

               String api_query_body = Mgmt_API_Object_get_by_by_id(uid);
               String api_query_respond = Mgmt_API_REST_Call("show-generic-object" , api_query_body, name, uid, type);  
               general_network_object net_object = read_logical_server(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(net_object);

               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_network_range net_range_object;

               // object ANY just fill standard values

               net_range_object = temp.new Object_network_range();
               net_range_object.name = net_object.name;
               net_range_object.type = net_object.type;
               net_range_object.address = net_object.address;
               net_range_object.extra_options = extra_option;
               net_range_object.logial_server_group = net_object.logical_server_group;
   
               net_range_object = calculate_network_range(net_range_object);
               add_network_object_to_range_set(net_range_object);


               return;

             }
             




            
            
            
                    
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE ANY CpmiAnyObject service
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  


             if (type.equals("CpmiAnyObject") && column.equals("service")) 
             {


                CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                CheckPoint_Management_API_Rule_Processor.Object_service_range srv_range_object;

                // object ANY just fill standard values

                 srv_range_object = temp.new Object_service_range();

                 srv_range_object.name = "Any";
                 srv_range_object.type = "CpmiAnyObject";
                 srv_range_object.start = "Any";
                 srv_range_object.end = "Any";
                 srv_range_object.protocol = "Any";   
                 srv_range_object.extra_options = extra_option;

                 srv_range_object.c_protocol = -1;
                 srv_range_object.c_icmp_type = -1;
                 srv_range_object.c_range_start = -1;
                 srv_range_object.c_range_stop = -1;
                 srv_range_object.c_app_id = -1;
                 
                 add_service_object_to_range_set(srv_range_object);

                 return;

             }
             
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE service-sctp
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  

                 

            if (type.equals("service-sctp")) 
            {

                     log_handler.log_in_gui(" Unsupported object: " + type + " " + name + " " + uid + "\n");
                     return;

            }

            //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE service
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
                

            if (type.startsWith("service")) 
            {


                    // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-" + type  , api_query_body, name, uid, type);  
               general_network_object service_object = read_service_object(api_query_respond);

               //  ad to global dictionary
               add_general_network_object_to_dictionary_set(service_object);


               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_service_range srv_range_object;


                srv_range_object = temp.new Object_service_range();
                srv_range_object.name = service_object.name;
                srv_range_object.type = service_object.type;
                srv_range_object.start = service_object.port_start;
                srv_range_object.end = service_object.port_end;
                srv_range_object.protocol = service_object.protocol;     
                srv_range_object.icmptype = service_object.icmptype;   
                srv_range_object.extra_options = extra_option;
                
                srv_range_object = calculate_service_range(srv_range_object); 
                add_service_object_to_range_set(srv_range_object);

               return;


            } 
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE application-site-group
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
          

            if (type.equals("application-site-group")) 
            {  

                    String api_query_body = Mgmt_API_Object_get_by_name(name);
                    String api_query_respond = Mgmt_API_REST_Call("show-application-site-group"  , api_query_body, name, uid, type);  

                    general_network_object service_object = read_group(api_query_respond);
                    add_general_network_object_to_dictionary_set(service_object);


                    int members_count = service_object.members.length;
                    for (int member = 0 ; member < members_count; member++)
                    {
                    // check objects nested in groups
                         calculate_object(service_object.members[member].name, service_object.members[member].uid, service_object.members[member].type, extra_option, "service", rule_number,  false);


                    }

                    return;
            }

                  
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE application-site-category
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
          

            if (type.equals("application-site-category")) 
            {

                String api_query_body = Mgmt_API_Object_get_by_name(name);
                String api_query_respond = Mgmt_API_REST_Call("show-application-site-category"  , api_query_body, name, uid, type);  

                general_network_object service_object = read_category(api_query_respond);
                add_general_network_object_to_dictionary_set(service_object);


                CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
                CheckPoint_Management_API_Rule_Processor.Object_service_range srv_range_object;

                Iterator iter =   url_category_database.iterator();
                
                while(iter.hasNext())
                {
                    url_category current_cat = (url_category) iter.next();
                    
                    if(service_object.name.equals(current_cat.name))
                    {
                        
                        
                        for (int app = 0 ; app < current_cat.apps.length ; app++)
                        {
                            String appname = current_cat.apps[app];
                        
                            ///////////////////////////////////////////////////////////////////////////////////////////////////
                            
                            
                            
                            
                            
                            
                            ////////////////////////////////////////////////////////////////////////////////////////////////////
                            calculate_object( appname, "" , "application-site" ,  extra_option,  column ,  rule_number,  true);
                            // przelicz wszystkie aplikacje ale nie pokazuj ich w wynikach
                        }
                        
                    }
                    
                }

                for ( int i = 0 ; i < service_object.application_service_ranges.length ; i++)
                {

                    srv_range_object = temp.new Object_service_range();
                    srv_range_object.name = service_object.name;
                    srv_range_object.type = service_object.type;

                    //srv_range_object.icmptype = service_object.icmptype;   
                    srv_range_object.extra_options = extra_option;
                    srv_range_object.app_service_nagate = service_object.negate_app_services;     
                    srv_range_object.app_id = service_object.app_id;

                    StringTokenizer st = new StringTokenizer(service_object.application_service_ranges[i] ,"/");

                    srv_range_object.app_service_type = st.nextToken();
                    srv_range_object.protocol = st.nextToken();

                    if (srv_range_object.protocol == null)
                    {

                        srv_range_object.protocol = "";

                    }
                    
                    if (srv_range_object.protocol.equals("TCP"))
                    {

                        srv_range_object.protocol = "6";

                    }
                    
                    if (srv_range_object.protocol.equals("UDP"))
                    {

                        srv_range_object.protocol = "17";

                    }
                    
                    if (srv_range_object.protocol.equals("ICMP"))
                    {

                        srv_range_object.protocol = "1";

                    }

                     String port_temp = st.nextToken();

                    if (port_temp == null)
                    {
                        port_temp = "Any";
                        srv_range_object.start  = "Any";
                        srv_range_object.end = "Any"; 
                    }


                    if (port_temp.contains("-"))
                    {
                        // port range
                        StringTokenizer st2 = new StringTokenizer(port_temp ,"-");

                        srv_range_object.start  = st2.nextToken();
                        srv_range_object.end = st2.nextToken();

                    }
                    else
                    {
                        // tylko port
                       srv_range_object.start = port_temp;
                       srv_range_object.end = port_temp;
                    }


                    srv_range_object.app_service = st.nextToken();

                    srv_range_object.name = service_object.name + " on " + srv_range_object.app_service;

                    if (srv_range_object.protocol == null)
                    {
                        srv_range_object.protocol = "";

                    }

                     if (srv_range_object.start == null)
                    {
                        srv_range_object.start = "";
                        srv_range_object.end = "";

                    }

                    if (srv_range_object.app_service_type == null)
                    {

                        srv_range_object.app_service_type = "";

                    }
                    
                 srv_range_object = calculate_service_range(srv_range_object);
                 add_service_object_to_range_set(srv_range_object);


                }

                return;

            }
                 
                  
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE application-site
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
          

            if (type.startsWith("application-site")) 
            {


                    // api call
               String api_query_body = Mgmt_API_Object_get_by_name(name);
               String api_query_respond = Mgmt_API_REST_Call("show-application-site"  , api_query_body, name, uid, type);  


               general_network_object service_object = read_applicaiton_site_object(api_query_respond);

               //  ad to global dictionary
                add_general_network_object_to_dictionary_set(service_object);


               CheckPoint_Management_API_Rule_Processor temp = new CheckPoint_Management_API_Rule_Processor();
               CheckPoint_Management_API_Rule_Processor.Object_service_range srv_range_object;

               for ( int i = 0 ; i < service_object.application_service_ranges.length ; i++)
               {

                    srv_range_object = temp.new Object_service_range();
                    srv_range_object.name = service_object.name;
                    srv_range_object.type = service_object.type;

                    //srv_range_object.icmptype = service_object.icmptype;   
                    srv_range_object.extra_options = extra_option;
                    srv_range_object.app_service_nagate = service_object.negate_app_services;     
                    srv_range_object.app_id = service_object.app_id;
                    srv_range_object.suppres_view = supress_view;


                    StringTokenizer st = new StringTokenizer(service_object.application_service_ranges[i] ,"/");

                    srv_range_object.app_service_type = st.nextToken();
                    srv_range_object.protocol = st.nextToken();

                    
                    if (srv_range_object.protocol == null)
                    {

                        srv_range_object.protocol = "";

                    }
                    
                    if (srv_range_object.protocol.equals("TCP"))
                    {

                        srv_range_object.protocol = "6";

                    }
                    
                    if (srv_range_object.protocol.equals("UDP"))
                    {

                        srv_range_object.protocol = "17";

                    }
                    
                    if (srv_range_object.protocol.equals("ICMP"))
                    {

                        srv_range_object.protocol = "1";

                    }

                    
                    if (srv_range_object.protocol == null)
                    {

                        srv_range_object.protocol = "Any";

                    }

                   String port_temp = st.nextToken();

                    if (port_temp == null)
                    {

                        port_temp = "Any";
                        srv_range_object.start  = "Any";
                        srv_range_object.end = "Any"; 
                    }

                    if (port_temp.contains("-"))
                    {
                        // port range
                        StringTokenizer st2 = new StringTokenizer(port_temp ,"-");
                        srv_range_object.start  = st2.nextToken();
                        srv_range_object.end = st2.nextToken();

                    }
                    else
                    {

                        // tylko port
                       srv_range_object.start = port_temp;
                       srv_range_object.end = port_temp;

                    }

                    srv_range_object.app_service = st.nextToken();

                    if (srv_range_object.app_service.contains("\\u003e0"))
                    {
                        
                        srv_range_object.app_service = srv_range_object.app_service.replace("\\u003e0", " >0");
                    }
                    
                    srv_range_object.name = service_object.name + " on " + srv_range_object.app_service;

                    if (srv_range_object.protocol == null)
                    {
                        srv_range_object.protocol = "";

                    }

                    if (srv_range_object.start == null)
                   {
                       srv_range_object.start = "";
                       srv_range_object.end = "";

                   }

                    if (srv_range_object.app_service_type == null)
                    {

                        srv_range_object.app_service_type = "";

                    }
                srv_range_object = calculate_service_range(srv_range_object);    
                add_service_object_to_range_set(srv_range_object);


               }


               return;

            }
            
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////
           // TYPE jakies gowno ktorego nie znamy
           //////////////////////////////////////////////////////////////////////////////////////////
           //////////////////////////////////////////////////////////////////////////////////////////  
          
            
           log_handler.log_in_gui(" Unsupported object: " + type + " " + name + " " + uid + "\n");
                 
                 
                 
           }
           catch (Exception e)
           {
               
               log_handler.log_in_gui("(CO) Error: " + e.getLocalizedMessage() + "\n", "40493", name + " " + uid + " " + type + " " + extra_option );
               
               
           }
                 

           
       }
       
    
    
     public Set<CheckPoint_Management_API_Rule_Processor.Object_network_range> calculate_network_ranges( CheckPoint_Management_API_Rule_Processor.Object_network[] network_array ,String rule_number)
       {
           
           
           
           try
           {
               
           
                // read source or destination filed to calculate ranges 

                 temporary_network_range_set =  new HashSet();    // temporary object
                 temporary_network_range_set.clear();
                //read network objects. one by one

                 for (int j = 0; j < network_array.length; j++)
                 {

                     // read objects added directlty to rule
                     calculate_object(network_array[j].name, network_array[j].uid, network_array[j].type, 0, "network" ,rule_number,  false);

                 }



                 return temporary_network_range_set;

            }
           catch (Exception e)
           {
               
               
               log_handler.log_in_gui("(CNR) Error: " + e.getLocalizedMessage(), "440619", "");
               
           }
           
           return null;
           
           
       }
       
  
     public Set<CheckPoint_Management_API_Rule_Processor.Object_service_range> calculate_service_ranges( CheckPoint_Management_API_Rule_Processor.Object_service[] service_array , String rule_number)
       {
           
           
           
           try
           {
               
           
                // read source or destination filed to calculate ranges 

                 temporary_service_range_set =  new HashSet();    // temporary object
                 temporary_service_range_set.clear();
                //read network objects. one by one

                 for (int j = 0; j < service_array.length; j++)
                 {

                     // read objects added directlty to rule
                     calculate_object(service_array[j].name, service_array[j].uid, service_array[j].type, 0, "service", rule_number,  false);

                 }



                 return temporary_service_range_set;

            }
           catch (Exception e)
           {
               
               
               log_handler.log_in_gui("(CSR) Error: " + e.getLocalizedMessage(), "911618", "");
               
           }
           
           return null;
           
           
       }
       


    
}
