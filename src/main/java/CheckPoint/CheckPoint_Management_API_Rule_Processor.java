/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package CheckPoint;

import General.Log;
import java.util.Iterator;
import java.util.Set;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;

/**
 *
 * @author Maciej
 */
public class CheckPoint_Management_API_Rule_Processor {

    /**
     * @param args the command line arguments
     */
    public Log log_handler;
    CheckPoint_Management_API_Object_Processor Object_Processor_Handler;
    public String FIREWALL_to_analyze;
    
    
    public  class Object_time
    {
        public String name = "";
        public String uid ="";

    }


    public  class Object_vpn
    {
        public String name = "";
        public String uid ="";

    }

 
    public  class Object_content
    {
        public String uid ="";
        public String name = "";
        public String type = "";

    }


    public  class Object_service
    {

        public String uid ="";
        public String name = "";
        public String type = "";
        public String port_start = "";
        public String port_end = "";
        public String protocol = "";
        public String icmptype = "";
        public boolean match_protocol = false;
        public boolean cluster_sync = false;    
        
        public int c_port_start;
        public int c_port_end;
        
    };
    
    
 
    public  class Object_network
    {
        public String uid ="";
        public String name = "";
        public String type = "";

        public String ipv4 = "";
        public String ipv6 = "";


    };

 
    public class Object_network_range
    {
        
        public String name = "";
        public String type = "";

        public String address = "";
        
        public String range_start = "";
        public String range_end   = "";
        
        public String network = "";
        public String network_subnet = "";
        
        public String ckp_interface = "";

        public int object_count = 0;

        int extra_options = 0;
        
        public String logial_server_group;
        
        public boolean suppres_view = false;
        
        // 0 - no options
        // 1 - excluded
        // 2 - 
        
        
        // do obliczen
                 
        long c_range_start;
        long c_range_stop;
        
        long c_wildcard_subnet;
        long c_wildcard_mask;


    }


    public  class Object_service_range
    {
        
        //public String uid ="";
        public String name = "";
        public String type = "";

        public String start = "";
        public String end = "";

        public String protocol = "";
        public String icmptype = "";
        int extra_options = 0;
        public String app_service = "";
        public String app_service_type = "";
        public boolean app_service_nagate = false; 
        public String app_id = "";
        
        public boolean suppres_view = false;
        
        // do obliczen
        
        long c_protocol ;
        long c_range_start;
        long c_range_stop;
        long c_app_id;
        long c_icmp_type;
        

        
        
    }

   
    public   class Object_install_on
    {
        
       public String name = "";
       public String uid ="";     
  
    }

    
    public  class Firewall_rule
    {
        
        public String uid ="";
        public String type = "";
        public String number = "" ;
        public String track = "";
        public String layer = "";
        public boolean track_per_session = false;
        public boolean track_per_connection = false;
        public boolean track_accounting = false;
        public boolean track_firewall_session = false;
        public String track_alert = "none";
        
        
        public Object_network[] source;
        public Object_network_range[] source_range;
        public boolean source_negate = false;
        
        
        public Object_network[] destination;
        public Object_network_range[] destination_range;
        public boolean destination_negate = false;

        public Object_service[]  service;
        public Object_service_range[] service_range;
        public String[] port;
        public boolean service_negate = false;

        public String action = "";
        public String action_layer = "";
        public boolean action_captive_portal = false;
        public String action_usercheck = "";
        
        public Object_content[] content;
        public boolean content_negate = false;
        public String content_direction = "";

        public String hits_level = "";
        public String hits_value = "";
        public String hits_percent = "";

        public String comment = "";
        public String name = "";
        public boolean enabled = true;

        public Object_vpn[] vpn;

        public Object_time[] time ;
        
        public Object_install_on[] install_on;

        public String rule_creator = "";
        public Long rule_creation_time ;
        
        public String rule_modifier = "";
        public Long rule_modify_time ;
        
        
        public String custom_filed1 = "";
        public String custom_filed2 = "";
        public String custom_filed3 = "";

        
         public String json;
        
    };

    
        public void merge_Object_Procesor( CheckPoint_Management_API_Object_Processor Object_Processor_Handler)
        {
            this.Object_Processor_Handler = Object_Processor_Handler;

        }

    
    
        public Firewall_rule process_section(JSONObject current_rule_object, String layer_name)
        {

            // processing section
            // just name and uid 
            Firewall_rule current_section = new Firewall_rule();
            
            try
            {
                // do zastapienia kiedys gsonem
                
            
                current_section.uid = (String)current_rule_object.get("uid");
                current_section.name = (String)current_rule_object.get("name");
                current_section.number = "";   // aviod null
                current_section.layer = layer_name;
                current_section.type = (String)current_rule_object.get("type");
                
                
                if (current_section.name == null)
                {

                    current_section.name = "New Section";
                }

                if (current_section.name.equals(""))
                {

                    current_section.name = "New Section";

                }
                    
                return current_section;
            
            }
            catch (Exception e)
            {
                
                log_handler.log_in_gui("(PS) Error:" + e.getMessage(), "55805" , current_rule_object.toJSONString());
                return current_section;
                
            }

            

        }
        
 
        public Firewall_rule process_rule(JSONObject rule_human_object,   String rule_number_prefix, String layer_name )
        {

            try
            {
            
            // all fields
            Firewall_rule current_rule = new Firewall_rule();
            
            current_rule.json = rule_human_object.toString();
            current_rule.uid = (String)rule_human_object.get("uid");
            current_rule.name = (String)rule_human_object.get("name");
            
            if (current_rule.name == null)
            {          
                current_rule.name = "";
                
            }
            
            current_rule.layer = layer_name;
            current_rule.type = (String)rule_human_object.get("type");      
            long rule_number = (long) rule_human_object.get("rule-number");
            current_rule.number = rule_number_prefix + rule_number;
      
            JSONObject js_track = (JSONObject) rule_human_object.get("track");
            JSONObject js_track_type = (JSONObject) js_track.get("type");
            current_rule.track =  (String)js_track_type.get("name");

            
            current_rule.track_per_session = (boolean) js_track.get("per-session") ;
            current_rule.track_per_connection = (boolean) js_track.get("per-connection") ;;
            current_rule.track_accounting = (boolean) js_track.get("accounting") ;;
            current_rule.track_firewall_session = (boolean) js_track.get("enable-firewall-session") ;;
            current_rule.track_alert = (String) js_track.get("alert") ;;
      
            current_rule.enabled = (boolean)rule_human_object.get("enabled");
 
            JSONObject js_hits = (JSONObject) rule_human_object.get("hits");
            current_rule.hits_level = (String) js_hits.get("level");
            long hits_value = (long) js_hits.get("value");
            current_rule.hits_value = Long.toString(hits_value);
            current_rule.hits_percent = (String)js_hits.get("percentage");
       
            current_rule.comment = (String) rule_human_object.get("comments");

            JSONArray source_array = (JSONArray) rule_human_object.get("source");
  
            Iterator i = source_array.iterator();
            int array_size = source_array.size();
            current_rule.source = new Object_network[array_size];
            int val = 0;
            
            while (i.hasNext()) 
            {
                JSONObject current_object = (JSONObject) i.next();


                current_rule.source[val] = new Object_network();
                current_rule.source[val].name = (String)current_object.get("name");
                current_rule.source[val].uid = (String)current_object.get("uid");
                current_rule.source[val].type = (String)current_object.get("type");
                current_rule.source[val].ipv4 = (String)current_object.get("ipv4-address");
                current_rule.source[val].ipv6 = (String)current_object.get("ipv6-address");

                val++;

                    
                    
            }
            current_rule.source_negate = (boolean) rule_human_object.get("source-negate");
            
            JSONArray destination_array = (JSONArray) rule_human_object.get("destination");
            i = destination_array.iterator();
            array_size = destination_array.size();
            
            current_rule.destination = new Object_network[array_size];
            val = 0;
            
        
            while (i.hasNext()) 
            {
                JSONObject current_object = (JSONObject) i.next();


                current_rule.destination[val] = new Object_network();

                current_rule.destination[val].name = (String)current_object.get("name");
                current_rule.destination[val].uid = (String)current_object.get("uid");
                current_rule.destination[val].type = (String)current_object.get("type");
                current_rule.destination[val].ipv4 = (String)current_object.get("ipv4-address");
                current_rule.destination[val].ipv6 = (String)current_object.get("ipv6-address");

                val++;
             
            }    
            
            current_rule.destination_negate = (boolean) rule_human_object.get("destination-negate");
            
        
            JSONArray service_array = (JSONArray) rule_human_object.get("service");
            i = service_array.iterator();
            array_size = service_array.size();
            
            current_rule.service = new Object_service[array_size];
            val = 0;
            
            
            while (i.hasNext()) 
            {
                
                JSONObject current_object = (JSONObject) i.next();
            
                 current_rule.service[val] = new Object_service();
                 
                 current_rule.service[val].name = (String)current_object.get("name"); 
                 current_rule.service[val].uid = (String)current_object.get("uid"); 
                 current_rule.service[val].type = (String)current_object.get("type"); 
                 
                 current_rule.service[val].port_start = (String)current_object.get("port"); 
                 current_rule.service[val].port_end = (String)current_object.get("port"); 
               
                 current_rule.service[val].protocol = (String)current_object.get("protocol"); 
                 
                if (Boolean.TRUE.equals((Boolean) current_object.get("match-by-protocol-signature")))
                {


                    current_rule.service[val].match_protocol = true; 
                }
                else
                {

                    current_rule.service[val].match_protocol = false;

                }

                if (Boolean.TRUE.equals((Boolean) current_object.get("sync-connections-on-cluster")))
                {


                    current_rule.service[val].cluster_sync = true; 
                }
                else
                {

                    current_rule.service[val].cluster_sync = false;

                }


                val++;
           
            
             }
            
            current_rule.service_negate = (boolean) rule_human_object.get("service-negate"); 
            
            JSONArray content_array = (JSONArray) rule_human_object.get("content");
            i = content_array.iterator();
            array_size = content_array.size();
            
            current_rule.content = new Object_content[array_size];
            val = 0;
           
           
            while (i.hasNext()) 
            {
                
                JSONObject current_object = (JSONObject) i.next();
            
                current_rule.content[val] = new Object_content();
                 
                current_rule.content[val].uid = (String)current_object.get("uid"); 
                current_rule.content[val].name = (String)current_object.get("name"); 
                 
                current_rule.content[val].type = (String)current_object.get("type"); 
                 
                val++;
            }
           
            
            current_rule.content_negate = (Boolean) rule_human_object.get("content-negate");
            current_rule.content_direction = (String) rule_human_object.get("content-direction");

          
            JSONArray time_array = (JSONArray) rule_human_object.get("time");
            i = time_array.iterator();
            array_size = time_array.size();
            
            current_rule.time = new Object_time[array_size];
            val = 0;
            
            while (i.hasNext()) 
            {
                
                JSONObject current_object = (JSONObject) i.next();
            
                current_rule.time[val] = new Object_time();               
                current_rule.time[val].uid = (String)current_object.get("uid"); 
                current_rule.time[val].name = (String)current_object.get("name"); 

                 val++;
                 
            }
              
            JSONArray vpn_array = (JSONArray) rule_human_object.get("vpn");
            i = vpn_array.iterator();
            array_size = vpn_array.size();
            
            current_rule.vpn = new Object_vpn[array_size];
            val = 0;
            
             while (i.hasNext()) 
            {
                
                JSONObject current_object = (JSONObject) i.next();
            
                current_rule.vpn[val] = new Object_vpn();  
                current_rule.vpn[val].name = (String)current_object.get("name"); 
                current_rule.vpn[val].uid = (String)current_object.get("uid"); 
             
                val++;
                 
            }
    
            JSONObject js_action = (JSONObject) rule_human_object.get("action");           
            current_rule.action =  (String)js_action.get("name");

            if (current_rule.action.equals("Inner Layer"))
            { 
             
           
                
               JSONObject js_action_layer =   (JSONObject) rule_human_object.get("inline-layer");
               current_rule.action_layer = (String) js_action_layer.get("name");
             
            }
             
            JSONObject js_usercheck = (JSONObject) rule_human_object.get("user-check");
             
            if (js_usercheck != null )
            {
                 JSONObject js_usercheck_interaction = (JSONObject) js_usercheck.get("interaction") ;           
                 current_rule.action_usercheck = (String) js_usercheck_interaction.get("name");
                 
            }
             else
             {
                 
                 current_rule.action_usercheck  = "";
                 
             }
             
            JSONObject js_action_settings = (JSONObject) rule_human_object.get("action-settings");
            if (Boolean.TRUE.equals((Boolean) js_action_settings.get("enable-identity-captive-portal")))
            {

               
                current_rule.action_captive_portal = true; 
            }
            else
            {

                current_rule.action_captive_portal = false;

            }
 
            JSONArray install_array = (JSONArray) rule_human_object.get("install-on");
            i = install_array.iterator();
            array_size = install_array.size();
            
            current_rule.install_on = new Object_install_on[array_size];
            val = 0;
            
            boolean found_in_targets = false;
            
            while (i.hasNext()) 
            {
                
                 JSONObject current_object = (JSONObject) i.next();
            
                 current_rule.install_on[val] = new Object_install_on();
                 
                 current_rule.install_on[val].name = (String)current_object.get("name"); 
                 current_rule.install_on[val].uid = (String)current_object.get("uid"); 
             
                 val++;
                 
            }
            
             
             if (current_rule.enabled == true)
             {
                 

                for (int j = 0 ; j < current_rule.install_on.length ; j++ )
                {

                    if (current_rule.install_on[j].name.equals("Policy Targets"))
                    {

                        found_in_targets = true;
                        break;
                    }

                    if (current_rule.install_on[j].name.equals(FIREWALL_to_analyze))
                    {

                        found_in_targets = true;
                        break;


                    }

                }

                
                if (found_in_targets == false)
                {
                    
                    current_rule.enabled = false;
                    
                    log_handler.log_in_gui(" Rule " + current_rule.number + ". Firewall not in policy targes. Rule disabled. \n");
                    
                }

                
                
                
                
             }
                    
             
            JSONObject js_custom_fields = (JSONObject) rule_human_object.get("custom-fields");
            current_rule.custom_filed1 =   (String) js_custom_fields.get("field-1");
            current_rule.custom_filed2 =   (String) js_custom_fields.get("field-2");
            current_rule.custom_filed3 =   (String) js_custom_fields.get("field-3");
          
            JSONObject js_meta = (JSONObject) rule_human_object.get("meta-info");
            current_rule.rule_creator = (String) js_meta.get("creator");
            current_rule.rule_modifier = (String) js_meta.get("last-modifier");
       
            JSONObject js_meta_creation = (JSONObject) js_meta.get("creation-time");
            current_rule.rule_creation_time = (Long) js_meta_creation.get("posix");
   
            JSONObject js_meta_modify = (JSONObject) js_meta.get("last-modify-time");
            current_rule.rule_modify_time = (Long) js_meta_modify.get("posix");
            
    
            // dodaj do reguly informacje i rangach jakie przetwarza
            // zamiana nazwy na adresy ip
        
            Set<CheckPoint_Management_API_Rule_Processor.Object_network_range>  temporary_source_range_set = Object_Processor_Handler.calculate_network_ranges(current_rule.source, current_rule.number);
      
            Iterator iter = temporary_source_range_set.iterator();

           
            current_rule.source_range = new Object_network_range[temporary_source_range_set.size()];
              
            val = 0;
            
             while(iter.hasNext())
            {
                
                
                Object_network_range onr = (Object_network_range) iter.next();
                
                current_rule.source_range[val] = new Object_network_range();               
                current_rule.source_range[val].name = onr.name;
                current_rule.source_range[val].type = onr.type;
                current_rule.source_range[val].extra_options = onr.extra_options;
                
                current_rule.source_range[val].c_range_start = onr.c_range_start;
                current_rule.source_range[val].c_range_stop = onr.c_range_stop;

                if (onr.type.equals("host"))
                {
                
                    current_rule.source_range[val].address = onr.address;
    
                }
                
                
                if (onr.type.equals("network"))
                {
                
                    current_rule.source_range[val].network = onr.network;
                    current_rule.source_range[val].network_subnet = onr.network_subnet;
                
                }
                
                 if (onr.type.equals("address-range"))
                {
                
                    current_rule.source_range[val].range_start = onr.range_start;
                    current_rule.source_range[val].range_end = onr.range_end;
                
                }
                
                   if (onr.type.equals("dynamic-object"))
                {
                
                    current_rule.source_range[val].range_start = onr.range_start;
                    current_rule.source_range[val].range_end = onr.range_end;
                    current_rule.source_range[val].suppres_view = onr.suppres_view;
                    current_rule.source_range[val].object_count = onr.object_count;
                
                }              
           
                if (onr.type.equals("updatable-object"))
                {
                
                    current_rule.source_range[val].range_start = onr.range_start;
                    current_rule.source_range[val].range_end = onr.range_end;
                    current_rule.source_range[val].suppres_view = onr.suppres_view;
                    current_rule.source_range[val].object_count = onr.object_count;
                   
                }    
                   
                if (onr.type.equals("dns-domain"))
                {
                    current_rule.source_range[val].name = onr.name;
                    current_rule.source_range[val].range_start = onr.range_start;
                    current_rule.source_range[val].range_end = onr.range_end;
                    current_rule.source_range[val].suppres_view = onr.suppres_view;
                    current_rule.source_range[val].object_count = onr.object_count;
                   
                   
                }    
                
                
                if (onr.type.equals("wildcard"))
                {
                
                    current_rule.source_range[val].network = onr.network;
                    current_rule.source_range[val].network_subnet = onr.network_subnet;
                
                    
                }
                
                if (onr.type.equals("checkpoint-host"))
                {
                
                    current_rule.source_range[val].address = onr.address;
   
                }
                
                
                if (onr.type.equals("simple-gateway"))
                {
                
                    current_rule.source_range[val].address = onr.address;
     
                }
               
                if (onr.type.equals("simple-cluster"))
                {
                
                    current_rule.source_range[val].address = onr.address;
                    
                
                }
               
                if (onr.type.equals("CpmiGatewayPlain"))
                {
                
                    current_rule.source_range[val].address = onr.address;
                    
                
                }
               
                if (onr.type.equals("CpmiOseDevice"))
                {
                
                    current_rule.source_range[val].address = onr.address;
                    
                
                }
                
                if (onr.type.equals("security-zone"))
                {
                
                    current_rule.source_range[val].network = onr.network;
                    current_rule.source_range[val].network_subnet = onr.network_subnet;
                    current_rule.source_range[val].ckp_interface = onr.ckp_interface;
                    
                }
                
                if (onr.type.equals("access-role"))
                {
                
                    current_rule.source_range[val].object_count = onr.object_count;

                    
                }
                
                if (onr.type.equals("data-center-object"))
                {
                
                    current_rule.source_range[val].object_count = onr.object_count;

                    
                }
                
                if (onr.type.equals("CpmiLogicalServer"))
                {
                
                    current_rule.source_range[val].address = onr.address;
                    current_rule.source_range[val].logial_server_group = onr.logial_server_group;
                
                }
           
                val++;
   
               
           }
    
             // --------------------------------------------------
             // destination --------------------------------------
             // --------------------------------------------------
             
             
            Set<CheckPoint_Management_API_Rule_Processor.Object_network_range>  temporary_destination_range_set = Object_Processor_Handler.calculate_network_ranges(current_rule.destination, current_rule.number);    
            iter = temporary_destination_range_set.iterator();

           
            current_rule.destination_range = new Object_network_range[temporary_destination_range_set.size()];
              
            val = 0;
            
             while(iter.hasNext())
            {
                
                
                Object_network_range onr = (Object_network_range) iter.next();
                
                current_rule.destination_range[val] = new Object_network_range();
                
                current_rule.destination_range[val].name = onr.name;
                current_rule.destination_range[val].type = onr.type;
                current_rule.destination_range[val].extra_options = onr.extra_options;
                
                current_rule.destination_range[val].c_range_start = onr.c_range_start;
                current_rule.destination_range[val].c_range_stop = onr.c_range_stop;

                
                if (onr.type.equals("host"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
                
                if (onr.type.equals("CpmiLogicalServer"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    current_rule.destination_range[val].logial_server_group = onr.logial_server_group;
                
                }
                
                

                
                if (onr.type.equals("network"))
                {
                
                    current_rule.destination_range[val].network = onr.network;
                    current_rule.destination_range[val].network_subnet = onr.network_subnet;
                
                }
                
                 if (onr.type.equals("address-range"))
                {
                
                    current_rule.destination_range[val].range_start = onr.range_start;
                    current_rule.destination_range[val].range_end = onr.range_end;
                
                }
                
                   if (onr.type.equals("dynamic-object"))
                {
                
                    current_rule.destination_range[val].range_start = onr.range_start;
                    current_rule.destination_range[val].range_end = onr.range_end;
                    current_rule.destination_range[val].suppres_view = onr.suppres_view;
                    current_rule.destination_range[val].object_count = onr.object_count;
                
                }              
           
                if (onr.type.equals("updatable-object"))
                {
                
                    current_rule.destination_range[val].range_start = onr.range_start;
                    current_rule.destination_range[val].range_end = onr.range_end;
                    current_rule.destination_range[val].suppres_view = onr.suppres_view;
                    current_rule.destination_range[val].object_count = onr.object_count;
                   
                }    
                   
                if (onr.type.equals("dns-domain"))
                {
                    current_rule.destination_range[val].name = onr.name;
                    current_rule.destination_range[val].range_start = onr.range_start;
                    current_rule.destination_range[val].range_end = onr.range_end;
                    current_rule.destination_range[val].suppres_view = onr.suppres_view;
                    current_rule.destination_range[val].object_count = onr.object_count;
                   
                   
                }    
                
                
                if (onr.type.equals("wildcard"))
                {
                
                    current_rule.destination_range[val].network = onr.network;
                    current_rule.destination_range[val].network_subnet = onr.network_subnet;
                
                    
                }
                
                if (onr.type.equals("checkpoint-host"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
                
                
                if (onr.type.equals("simple-gateway"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
               
                if (onr.type.equals("simple-cluster"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
               
                if (onr.type.equals("CpmiGatewayPlain"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
               
                if (onr.type.equals("CpmiOseDevice"))
                {
                
                    current_rule.destination_range[val].address = onr.address;
                    
                
                }
                
                if (onr.type.equals("security-zone"))
                {
                
                    current_rule.destination_range[val].network = onr.network;
                    current_rule.destination_range[val].network_subnet = onr.network_subnet;
                    current_rule.destination_range[val].ckp_interface = onr.ckp_interface;
                    
                }
                
                if (onr.type.equals("access-role"))
                {
                
                    current_rule.destination_range[val].object_count = onr.object_count;

                    
                }
                
                if (onr.type.equals("data-center-object"))
                {
                
                    current_rule.destination_range[val].object_count = onr.object_count;

                    
                }
                
               
                val++;
      
           }
    
                  
             
          // ------------------------------------------
          // service
          // ------------------------------------------
          
            Set<CheckPoint_Management_API_Rule_Processor.Object_service_range>  temporary_service_range_set = Object_Processor_Handler.calculate_service_ranges(current_rule.service , current_rule.number);

            iter = temporary_service_range_set.iterator();


            current_rule.service_range = new Object_service_range[temporary_service_range_set.size()];

            val = 0;

            while(iter.hasNext())
            {
                
                
                Object_service_range osr = (Object_service_range) iter.next();
                
                current_rule.service_range[val] = new Object_service_range();
                
                current_rule.service_range[val].name = osr.name;
                current_rule.service_range[val].start = osr.start;
                current_rule.service_range[val].end = osr.end;
              
                current_rule.service_range[val].protocol = osr.protocol;
                current_rule.service_range[val].icmptype = osr.icmptype;
                
                current_rule.service_range[val].type = osr.type;
                current_rule.service_range[val].extra_options = osr.extra_options;
                current_rule.service_range[val].app_service = osr.app_service;
                current_rule.service_range[val].app_service_type = osr.app_service_type;
                current_rule.service_range[val].app_service_nagate = osr.app_service_nagate;
                current_rule.service_range[val].app_id = osr.app_id;
                
                current_rule.service_range[val].c_range_start = osr.c_range_start;
                current_rule.service_range[val].c_range_stop = osr.c_range_stop;
                current_rule.service_range[val].c_protocol = osr.c_protocol;
                current_rule.service_range[val].c_icmp_type = osr.c_icmp_type;
                current_rule.service_range[val].c_app_id = osr.c_app_id;
                
                current_rule.service_range[val].suppres_view = osr.suppres_view;
                val++;
                
            }
                         
            return current_rule;


            
            }
            catch( Exception e)
            {
                
                
                    log_handler.log_in_gui("(PR) Error: " + e.getLocalizedMessage(), "59595" , rule_human_object.toJSONString()  + " " + rule_number_prefix );

                    return null;
                    
            }
  
 


        }



    
    
    
    
}
