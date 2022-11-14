package com.hedera.platform.bls;

import com.goterl.resourceloader.ResourceLoader;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * A simple library class which helps with loading dynamic library stored in the JAR archive
 *
 * @see <a
 * 		href="http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar">http://adamheinrich
 * 		.com/blog/2012/how-to-load-native-jni-library-from-jar</a>
 * @see <a href="https://github.com/adamheinrich/native-utils">https://github.com/adamheinrich/native-utils</a>
 */
public final class LibraryLoader {
	private static final String LIBRARY_NAME = "libhedera_bls_jni";

	private final Logger logger = LogManager.getLogger(LibraryLoader.class);

	/**
	 * Constructor
	 */
	public LibraryLoader() {
	}

	/**
	 * Loads library from the current JAR archive and registers the native methods
	 * of {@link #classes}. The library will be loaded at most once.
	 *
	 * <p>The file from JAR is copied into system temporary directory and then loaded.
	 * The temporary file is deleted after exiting.
	 */
	public void loadBundledLibrary(final Class<?> clazz) throws IOException {
		String pathInJar = getLibraryPathInResources();

		try {
			final File resourceFile = copyToTempDirectory(pathInJar, clazz);
			System.load(resourceFile.getAbsolutePath());
		} catch (final URISyntaxException e) {
			System.out.println(e);
		}
	}

	/**
	 * Copies a file into a temporary directory regardless of
	 * if it is in a JAR or not.
	 *
	 * @param relativePath
	 * 		A relative path to a file or directory
	 * 		relative to the resources folder.
	 * @return The file or directory you want to load.
	 * @throws IOException
	 * 		If at any point processing of the resource file fails.
	 * @throws URISyntaxException
	 * 		If cannot find the resource file.
	 */
	public File copyToTempDirectory(String relativePath, Class outsideClass) throws IOException, URISyntaxException {
		// Create a "main" temporary directory in which
		// everything can be thrown in.
		File mainTempDir = ResourceLoader.createMainTempDirectory();

		// Create the required directories.
		mainTempDir.mkdirs();

		// Is the user loading resources that are
		// from inside a JAR?
		URL fullJarPathURL = ResourceLoader.getThePathToTheJarWeAreIn(outsideClass);

		// Test if we are in a JAR and if we are
		// then do the following...
		if (isJarFile(fullJarPathURL)) {
			File extracted = extractFromWithinAJarFile(fullJarPathURL, mainTempDir, relativePath);
			if (extracted != null) {
				return extracted;
			}
		}

		// If not then get the file/directory
		// straight from the file system
		return getFileFromFileSystem(relativePath, mainTempDir);
	}

	/**
	 * Does the URL lead to a valid JAR file? Usually
	 * valid JAR files have a manifest.
	 *
	 * @param jarUrl
	 * @return
	 */
	private boolean isJarFile(URL jarUrl) {
		if (jarUrl != null) {
			String[] split = jarUrl.getPath().split("(\\.jar/)");
			String path;
			if (split.length == 1) {
				path = jarUrl.getPath();
			} else {
				path = split[0] + ".jar";
			}

			try (JarFile jarFile = new JarFile(path)) {
				// Successfully opened the jar file. Check if there's a manifest
				// This is probably not necessary
				Manifest manifest = jarFile.getManifest();
				if (manifest != null) {
					return true;
				}
			} catch (IOException | IllegalStateException | SecurityException e) {
				logger.debug("This is not a JAR file due to {}", e.getMessage());
			}
		}
		return false;
	}

	/**
	 * If we're not in a JAR then we can load directly from the file system
	 * without all the unzipping fiasco present in {@see #getFileFromJar}.
	 *
	 * @param relativePath
	 * 		A relative path to a file or directory in the resources folder.
	 * @param outputDir
	 * 		A directory in which to store loaded files. Preferentially a temporary one.
	 * @return The file or directory that was requested.
	 * @throws IOException
	 * 		Could not find your requested file.
	 */
	private File getFileFromFileSystem(String relativePath, File outputDir) throws IOException, URISyntaxException {
		relativePath = prefixStringWithSlashIfNotAlready(relativePath);
		final URL url = ResourceLoader.class.getResource(relativePath);
		final String urlString = url.getFile();
		final File file;
		if (Platform.isWindows()) {
			file = Paths.get(url.toURI()).toFile();
		} else {
			file = new File(urlString);
		}

		if (file.isFile()) {
			File resource = new File(relativePath);
			File resourceCopiedToTempFolder = new File(outputDir, resource.getName());
			doCopyFile(file, resourceCopiedToTempFolder);
			return resourceCopiedToTempFolder;
		} else {
			copyDirectory(file, outputDir);
			return outputDir;
		}
	}

	private static final long FILE_COPY_BUFFER_SIZE = 1000000 * 30;

	/**
	 * From Apache Commons
	 *
	 * @param srcFile
	 * 		The source file
	 * @param destFile
	 * 		The destination file
	 * @throws IOException
	 */
	private static void doCopyFile(final File srcFile, final File destFile)
			throws IOException {
		if (destFile.exists() && destFile.isDirectory()) {
			throw new IOException("Destination '" + destFile + "' exists but is a directory");
		}

		try (FileInputStream fis = new FileInputStream(srcFile);
			 FileChannel input = fis.getChannel();
			 FileOutputStream fos = new FileOutputStream(destFile);
			 FileChannel output = fos.getChannel()) {
			final long size = input.size(); // TODO See IO-386
			long pos = 0;
			long count = 0;
			while (pos < size) {
				final long remain = size - pos;
				count = remain > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : remain;
				final long bytesCopied = output.transferFrom(input, pos, count);
				if (bytesCopied == 0) { // IO-385 - can happen if file is truncated after caching the size
					break; // ensure we don't loop forever
				}
				pos += bytesCopied;
			}
		}

		final long srcLen = srcFile.length(); // TODO See IO-386
		final long dstLen = destFile.length(); // TODO See IO-386
		if (srcLen != dstLen) {
			throw new IOException("Failed to copy full contents from '" +
					srcFile + "' to '" + destFile + "' Expected length: " + srcLen + " Actual: " + dstLen);
		}
	}

	/**
	 * From Apache Commons
	 *
	 * @param srcDir
	 * 		The source directory
	 * @param destDir
	 * 		The destination directory
	 * @throws IOException
	 */
	private static void copyDirectory(final File srcDir, final File destDir) throws IOException {
		if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
			throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
		}

		// Cater for destination being directory within the source directory (see IO-141)
		List<String> exclusionList = null;
		if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
			final File[] srcFiles = srcDir.listFiles();
			if (srcFiles != null && srcFiles.length > 0) {
				exclusionList = new ArrayList<>(srcFiles.length);
				for (final File srcFile : srcFiles) {
					final File copiedFile = new File(destDir, srcFile.getName());
					exclusionList.add(copiedFile.getCanonicalPath());
				}
			}
		}
		doCopyDirectory(srcDir, destDir, exclusionList);
	}

	private static void doCopyDirectory(final File srcDir, final File destDir, final List<String> exclusionList)
			throws IOException {
		// recurse
		final File[] srcFiles = srcDir.listFiles();
		if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
			throw new IOException("Failed to list contents of " + srcDir);
		}
		if (destDir.exists()) {
			if (destDir.isDirectory() == false) {
				throw new IOException("Destination '" + destDir + "' exists but is not a directory");
			}
		} else {
			if (!destDir.mkdirs() && !destDir.isDirectory()) {
				throw new IOException("Destination '" + destDir + "' directory cannot be created");
			}
		}
		if (destDir.canWrite() == false) {
			throw new IOException("Destination '" + destDir + "' cannot be written to");
		}
		for (final File srcFile : srcFiles) {
			final File dstFile = new File(destDir, srcFile.getName());
			if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
				if (srcFile.isDirectory()) {
					doCopyDirectory(srcFile, dstFile, exclusionList);
				} else {
					doCopyFile(srcFile, dstFile);
				}
			}
		}
	}

	public File extractFromWithinAJarFile(URL jarPath, File mainTempDir, String relativePath)
			throws IOException, URISyntaxException {
		if (jarPath == null) {
			return null;
		}
		// Split our JAR path
		String fullPath = jarPath + prefixStringWithSlashIfNotAlready(relativePath);
		return nestedExtract(mainTempDir, fullPath);
	}

	/**
	 * If the string does not start with a slash, then
	 * // make sure it does.
	 *
	 * @param s
	 * 		A string to prefix
	 * @return A string with a slash prefixed
	 */
	private String prefixStringWithSlashIfNotAlready(String s) {
		if (!s.startsWith("/")) {
			s = "/" + s;
		}
		return s;
	}

	/**
	 * A method that keeps extracting JAR files from within each other.
	 * This method only allows a maximum nested depth of 20.
	 *
	 * @param extractTo
	 * 		Where shall we initially extract files to.
	 * @param fullPath
	 * 		The full path to the initial
	 * @return The final extracted file.
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	private File nestedExtract(File extractTo, String fullPath) throws IOException, URISyntaxException {
		final String JAR = ".jar";

		// After this line we have something like
		// file:C/app, some/lazysodium, file.txt
		String[] split = fullPath.split("(\\.jar/)");

		if (split.length > 20) {
			// What monster would put a JAR in a JAR 20 times?
			throw new StackOverflowError("We cannot extract a file 21 or more layers deep.");
		}

		// We have no ".jar/" so we go straight
		// to extraction.
		if (split.length == 1) {
			logger.debug("Extracted {} to {}", fullPath, extractTo.getAbsolutePath());
			return extractFilesOrFoldersFromJar(extractTo, new URL(fullPath), "");
		}

		String currentExtractionPath = "";
		File extracted = null;
		File nestedExtractTo = extractTo;
		for (int i = 0; i < split.length - 1; i++) {
			// Remember part = "file:C/app". But we need to know
			// where to extract these files. So we have
			// to prefix it with the current extraction path. We can't
			// just dump everything in the temp directory all the time.
			// Of course, we also suffix it with a ".jar". So at the end,
			// we get something like "file:C:/temp/app.jar"
			String part = currentExtractionPath + split[i] + JAR;
			// If we don't add this then when we pass it into
			// a URL() object then the URL object will complain
			if (!part.startsWith("file:")) {
				part = "file:" + part;
			}

			// Now, we need to "look ahead" and determine
			// the next part. We'd get something like
			// this: "/lazysodium".
			String nextPart = "/" + split[i + 1];

			// Now check if it's the last iteration of this for-loop.
			// If it isn't then add a ".jar" to nextPart, resulting
			// in something like "/lazysodium.jar"
			boolean isLastIteration = (i == (split.length - 2));
			if (!isLastIteration) {
				nextPart = nextPart + JAR;
			}

			// Now perform the extraction.
			logger.debug("Extracting {} from {}", nextPart, part);
			extracted = extractFilesOrFoldersFromJar(nestedExtractTo, new URL(part), nextPart);
			logger.debug("Extracted: {}", extracted.getAbsolutePath());

			// Note down the parent folder's location of the file we extracted to.
			// This will be used at the start of the for-loop as the
			// new destination to extract to.
			currentExtractionPath = nestedExtractTo.getAbsolutePath() + "/";
			nestedExtractTo = extracted.getParentFile();
		}
		return extracted;
	}

	/**
	 * Extracts a file/directory from a JAR. A JAR is simply
	 * a zip file. We can unzip it and get our file successfully.
	 *
	 * @param jarUrl
	 * 		A JAR's URL.
	 * @param outputDir
	 * 		A directory of where to store our extracted files.
	 * @param pathInJar
	 * 		A relative path to a file that is in our resources folder.
	 * @return The file or directory that we requested.
	 * @throws URISyntaxException
	 * 		If we could not ascertain our location.
	 * @throws IOException
	 * 		If whilst unzipping we had some problems.
	 */
	private File extractFilesOrFoldersFromJar(File outputDir, URL jarUrl, String pathInJar) throws URISyntaxException,
			IOException {
		File jar = ResourceLoader.urlToFile(jarUrl);
		unzip(jar.getAbsolutePath(), outputDir.getAbsolutePath());
		String filePath = outputDir.getAbsolutePath() + pathInJar;
		return new File(filePath);
	}

	/**
	 * From https://www.javadevjournal.com/java/zipping-and-unzipping-in-java/
	 *
	 * @param zipFilePath
	 * 		An absolute path to a zip file
	 * @param unzipLocation
	 * 		Where to unzip the zip file
	 * @throws IOException
	 * 		If could not unzip.
	 */
	private static void unzip(final String zipFilePath, final String unzipLocation) throws IOException {
		if (!(Files.exists(Paths.get(unzipLocation)))) {
			Files.createDirectories(Paths.get(unzipLocation));
		}
		try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))) {
			ZipEntry entry = zipInputStream.getNextEntry();
			while (entry != null) {
				Path filePath = Paths.get(unzipLocation, entry.getName());
				if (!entry.isDirectory()) {
					filePath.getParent().toFile().mkdirs();
					unzipFiles(zipInputStream, filePath);
				} else {
					Files.createDirectories(filePath);
				}

				zipInputStream.closeEntry();
				entry = zipInputStream.getNextEntry();
			}
		}
	}

	private static void unzipFiles(final ZipInputStream zipInputStream, final Path unzipFilePath) throws IOException {
		try (BufferedOutputStream bos = new BufferedOutputStream(
				new FileOutputStream(unzipFilePath.toAbsolutePath().toString()))) {
			byte[] bytesIn = new byte[1024];
			int read = 0;
			while ((read = zipInputStream.read(bytesIn)) != -1) {
				bos.write(bytesIn, 0, read);
			}
		}
	}

	/**
	 * Returns the absolute path to sodium library inside JAR (beginning with '/')
	 *
	 * @return The path to the library binary
	 */
	public static String getLibraryPathInResources() {
		boolean is64Bit = Native.POINTER_SIZE == 8;
		if (Platform.isWindows()) {
			final String platformFolder = "windows";
			final String fileName = LIBRARY_NAME + ".dll";

			if (is64Bit) {
				return getPath(List.of(platformFolder, "windows64", fileName));
			} else {
				return getPath(List.of(platformFolder, "windows", fileName));
			}
		}
		if (Platform.isMac()) {
			final String platformFolder = "mac";
			final String fileName = LIBRARY_NAME + ".dylib";

			// check for Apple Silicon
			if (Platform.isARM()) {
				return getPath(List.of(platformFolder, "aarch64", fileName));
			} else {
				return getPath(List.of(platformFolder, "intel", fileName));
			}
		}
		if (Platform.isLinux()) {
			final String platformFolder = "linux";
			final String fileName = LIBRARY_NAME + ".so";

			if (is64Bit) {
				return getPath(List.of(platformFolder, "linux64", fileName));
			} else {
				return getPath(List.of(platformFolder, "linux", fileName));
			}
		}

		String message = String.format("Unsupported platform: %s/%s", System.getProperty("os.name"),
				System.getProperty("os.arch"));

		throw new LibraryLoadingException(message);
	}

	private static String getPath(final List<String> elements) {
		StringBuilder output = new StringBuilder();

		for (int i = 0; i < elements.size() - 1; ++i) {
			output.append(elements.get(i)).append("/");
		}

		output.append(elements.get(elements.size() - 1));

		return output.toString();
	}
}
