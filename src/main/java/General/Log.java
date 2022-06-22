/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package General;

import java.io.File;  
import java.io.IOException;  
import javax.swing.text.StyledDocument;
import java.io.FileWriter; 
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;  
import java.time.format.DateTimeFormatter;
import java.time.LocalDateTime;
import java.time.format.FormatStyle;
/**
 *
 * @author Maciej
 */
public class Log
{

    public boolean debug_messages_enabled = false;
    
    javax.swing.JTextPane log_area;
    StyledDocument document;
    
    File log_file_error;
    File log_file_debug;
    
    public Log(javax.swing.JTextPane log_area)
    {
       
        this.log_area = log_area;
        this.log_area.setContentType("text/html");
        document = (StyledDocument) log_area.getDocument();
        log_file_error = new File("error.log");
        log_file_debug = new File("debug.log");
        
    }
    
    public void refresh_log_area()
    {
        try
        {

            log_area.update(log_area.getGraphics());
            Thread.sleep(100);

        }
        catch (Exception e)
        {
            
            
            
        }
    }
    
    
    public void log_in_file(String message)
    {
        
       
        String date_time = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).format(LocalDateTime.now());
        
        try
        {
            
            
             FileWriter debug_file_writer = new FileWriter(log_file_debug);
             FileWriter error_file_writer = new FileWriter(log_file_error);
   
            if (!log_file_debug.exists())
            {
                log_file_debug.createNewFile();

                
            }
       
            if (!log_file_error.exists())
            {
                log_file_error.createNewFile();
                
            }

            
            if (debug_messages_enabled)
            {
                
                debug_file_writer.write(date_time + ": " + message + "\n");
                debug_file_writer.flush();
                error_file_writer.write(date_time + ": " + message + "\n");
                error_file_writer.flush();
                
            }
            else
            {
                
               
                error_file_writer.write(date_time + ": " + message + "\n");
                error_file_writer.flush();
                
            }
            
            
          
            
        }
        catch (Exception e)
        {

            
              System.out.println("ERROR (log-lif): " + e.getMessage());

        }

    }
    
    
    public void log_in_gui(String message, String error_code , String extra_msg)
    {
       
             
        try
        {
      
         
            if (debug_messages_enabled == true)
            {
                // 
                //  log everything
                //

                  document.insertString(document.getLength(), message, null);
               
            }
            else   
            {

                //
                // debug disabled
                //

                if (message.startsWith("[DEBUG]"))
                {

                    return;
                }
                
                if (error_code.equals(""))
                {
                    
                    message = error_code + " " + message;
                    
                }
                else
                {
                    
                    message = "%" + error_code + " " + message;
                }
                
                document.insertString(document.getLength(), message, null);
                Thread.sleep(100);
            }
            
        } catch (Exception e)
        {
            
            System.out.println("ERROR (log-lig): " + e.getMessage());
            
        }
                
        
        
    }
    
    public void log_in_gui(String message)
    {
       
             
        try
        {
            
       
         
            if (debug_messages_enabled == true)
            {
                // 
                //  log everything
                //

                  document.insertString(document.getLength(), message, null);
               
            }
            else   
            {

                //
                // debug disabled
                //

                if (message.startsWith("[DEBUG]"))
                {

                    return;
                }
               
               document.insertString(document.getLength(), message, null);

            }
            
        } catch (Exception e)
        {
            
            System.out.println("ERROR (log-lig): " + e.getMessage());
            
        }
                
        
        
    } 
    
    
    
    
    
}
