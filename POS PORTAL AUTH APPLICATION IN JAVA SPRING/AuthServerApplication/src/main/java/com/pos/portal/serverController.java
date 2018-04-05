package com.pos.portal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Principal;

@RestController
@RequestMapping("/rest/hello")
public class serverController {

	@GetMapping("/principal")
	public Principal user(Principal principal) {
		return principal;
	}

	@GetMapping
	public String hello() {
		return "Hello World";
	}

	//@RequestMapping(value = "/upload", method="POST")
	@PreAuthorize("#oauth2.hasScope('read')")
	@PostMapping(value = "/upload")
	
	public String uploadFile(@RequestParam("uploadedFile") MultipartFile uploadedFileRef) {
		// Get name of uploaded file.
		String fileName = uploadedFileRef.getOriginalFilename();

		// Path where the uploaded file will be stored.
		String path = "E:/" + fileName;

		// This buffer will store the data read from 'uploadedFileRef'
		byte[] buffer = new byte[1000];

		// Now create the output file on the server.
		File outputFile = new File(path);

		FileInputStream reader = null;
		FileOutputStream writer = null;
		int totalBytes = 0;
		try {
			outputFile.createNewFile();

			// Create the input stream to uploaded file to read data from it.
			reader = (FileInputStream) uploadedFileRef.getInputStream();

			// Create writer for 'outputFile' to write data read from
			// 'uploadedFileRef'
			writer = new FileOutputStream(outputFile);

			// Iteratively read data from 'uploadedFileRef' and write to
			// 'outputFile';
			int bytesRead = 0;
			while ((bytesRead = reader.read(buffer)) != -1) {
				writer.write(buffer);
				totalBytes += bytesRead;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				reader.close();
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		return "File uploaded successfully! Total Bytes Read=" + totalBytes;
	}
	
	

}
