package com.docusign.example.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.*;

public class DSHelper {
    private static final ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    /**
     * This method read bytes content from resource
     *
     * @param path - resource path
     * @return - return bytes array
     * @throws IOException
     */
    public static byte[] readContent(String path) throws IOException {

        InputStream is = DSHelper.class.getResourceAsStream("/"+path);

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;

        byte[] data = new byte[1024];

        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();
        return buffer.toByteArray();
    }

    /**
     * This method create temporary file from private key string
     *
     * @param fileSuffix - file name suffex
     * @return
     * @throws IOException
     */
    public static File createPrivateKeyTempFile(String fileSuffix) throws IOException {

        File temp = null;
        BufferedWriter writer = null;

        try {
            temp = File.createTempFile(fileSuffix,".tmp");
            writer = new BufferedWriter(new FileWriter(temp.getAbsolutePath()));
            writer.write(DSConfig.PRIVATE_KEY);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if(writer != null){
                writer.close();
            }
        }

        return temp;
    }

    /**
     * This method check if directory exists and if not it create it.
     *
     * @param dirName - directory path
     * @return - returns absolute path
     */
    public static String ensureDirExistance(String dirName) {
        File dir = new File(dirName);

        if(!dir.exists()){
            dir.mkdirs();
        }

        return dir.getAbsolutePath();
    }

    /**
     * This method to write byte array to file
     * @param path - path to file
     * @param bytesArray - byte array to write
     * @throws IOException
     */
    public static void writeByteArrayToFile(String path, byte [] bytesArray) throws IOException {

        try (FileOutputStream fos = new FileOutputStream(path)){
            fos.write(bytesArray);
        }

    }

    /**
     * This method printing pretty json format
     * @param arg - any object to be written as string
     */
    public static void printPrettyJSON(Object arg) {
        try {
            String jsonInString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(arg);
            System.out.println("Results:");
            System.out.println(jsonInString);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
    }
}
