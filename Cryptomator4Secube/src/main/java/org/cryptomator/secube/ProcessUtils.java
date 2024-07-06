package org.cryptomator.secube;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.List;

public class ProcessUtils {
	
	/**
     * Reads the output from a given Process.
     * 
     * @param process The Process from which to read the output.
     * @return The output of the Process as a String.
     * @throws Exception If an I/O error occurs.
     */
	public static String readFromProcess(Process process) throws Exception {
		InputStream stdin = process.getInputStream();
        InputStreamReader isr = new InputStreamReader(stdin);
        BufferedReader br = new BufferedReader(isr);
        StringBuilder sb = new StringBuilder();
        String s1;
        
        try {
			while ((s1 = br.readLine()) != null) {
			    sb.append(s1).append("\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
        
        return sb.toString();
	}
	
	/**
     * Writes a list of data to the input of a given Process.
     * 
     * @param <T> The type of data to write.
     * @param process The Process to which the data will be written.
     * @param data The List of data to write to the process.
     * @throws Exception If an I/O error occurs.
     */
	public static <T> void writeOnProcess(Process process, List<T> data) throws Exception {
		OutputStream os = process.getOutputStream();
        PrintWriter pw = new PrintWriter(os);
        for(T elem : data) {
        	pw.println(elem);
        }
        pw.flush();
	}
}
