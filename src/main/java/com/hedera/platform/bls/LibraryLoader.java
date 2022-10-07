package com.hedera.platform.bls;

/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

import com.goterl.resourceloader.SharedLibraryLoader;
import com.sun.jna.Native;
import com.sun.jna.Platform;

import java.util.ArrayList;
import java.util.List;

/**
 * A simple library class which helps with loading dynamic library stored in the JAR archive. Works with JNA.
 *
 * <p>This class is thread-safe.
 *
 * @see <a
 * 		href="http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar">http://adamheinrich
 * 		.com/blog/2012/how-to-load-native-jni-library-from-jar</a>
 * @see <a href="https://github.com/adamheinrich/native-utils">https://github.com/adamheinrich/native-utils</a>
 */
public final class LibraryLoader {
	private static final String LIBRARY_NAME = "libpairings_jni_rust";

	private LibraryLoader() {
	}

	/**
	 * Loads library from the current JAR archive and registers the native methods
	 * of {@link #classes}. The library will be loaded at most once.
	 *
	 * <p>The file from JAR is copied into system temporary directory and then loaded.
	 * The temporary file is deleted after exiting.
	 */
	public static void loadBundledLibrary(final Class<?> clazz) {
		String pathInJar = getLibraryPathInResources();
		SharedLibraryLoader.get().load(pathInJar, clazz);
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