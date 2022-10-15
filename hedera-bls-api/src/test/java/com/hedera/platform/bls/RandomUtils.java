package com.hedera.platform.bls;


import java.security.SecureRandom;
import java.util.Random;

public class RandomUtils {
	private RandomUtils() {
	}

	private static final Random RANDOM = new SecureRandom();

	public static int randomPositiveInt(final Random random, final int maxValue) {
		return random.ints(1, 1, maxValue).findFirst().orElseThrow();
	}

	public static int randomPositiveInt(final Random random) {
		return randomPositiveInt(random, Integer.MAX_VALUE);
	}

	public static byte[] randomByteArray(final Random random, final int size) {
		final byte[] bytes = new byte[size];
		random.nextBytes(bytes);
		return bytes;
	}

	public static Random getRandomPrintSeed() {
		return getRandom(true);
	}

	public static Random getRandom() {
		return getRandom(false);
	}

	private static Random getRandom(final boolean printSeed) {
		final long seed = RANDOM.nextLong();
		if (printSeed) {
			System.out.println("Random seed: " + seed);
		}
		return new Random(seed);
	}

	public static Random initRandom(final long seed) {
		return new Random(seed);
	}
}
