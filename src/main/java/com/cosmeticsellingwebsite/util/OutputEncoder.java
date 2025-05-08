package com.cosmeticsellingwebsite.util;

import org.springframework.web.util.HtmlUtils;

/**
 * Utility class to help prevent XSS attacks with output encoding
 */
public class OutputEncoder {

    /**
     * Encodes the HTML content to prevent XSS attacks
     * 
     * @param input The input string to be encoded
     * @return The HTML encoded string
     */
    public static String encodeHtml(String input) {
        if (input == null) {
            return "";
        }
        return HtmlUtils.htmlEscape(input);
    }
    
    /**
     * Encodes the HTML attributes to prevent XSS attacks
     * 
     * @param input The input string to be encoded
     * @return The HTML attribute encoded string
     */
    public static String encodeHtmlAttribute(String input) {
        if (input == null) {
            return "";
        }
        return HtmlUtils.htmlEscape(input);
    }
    
    /**
     * Encodes JavaScript content to prevent XSS attacks
     * 
     * @param input The input string to be encoded
     * @return The JavaScript encoded string
     */
    public static String encodeJavaScript(String input) {
        if (input == null) {
            return "";
        }
        // Encode quotes and other special characters
        String escaped = input.replace("\\", "\\\\")
                             .replace("\"", "\\\"")
                             .replace("'", "\\'")
                             .replace("\n", "\\n")
                             .replace("\r", "\\r")
                             .replace("<", "\\u003c")
                             .replace(">", "\\u003e")
                             .replace("&", "\\u0026");
        return escaped;
    }
}
