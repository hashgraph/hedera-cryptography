/*
 * Copyright (C) 2024 Hedera Hashgraph, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hedera.cryptography.tss.extensions;

import static com.hedera.cryptography.tss.extensions.LagrangeTests.Point.p;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.hedera.cryptography.pairings.api.Curve;
import com.hedera.cryptography.pairings.api.Field;
import com.hedera.cryptography.pairings.api.FieldElement;
import com.hedera.cryptography.pairings.api.Group;
import com.hedera.cryptography.pairings.api.GroupElement;
import com.hedera.cryptography.pairings.api.PairingFriendlyCurves;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

public class LagrangeTests {

    // 30 - (125 x)/3 + 25 x^2 - (10 x^3)/3
    // {{1,10},{2,20},{3,40},{4,50}}
    private final Point[] INPUT_0 = new Point[] {p(1, 10), p(2, 20), p(3, 40), p(4, 50)};
    // -54 + (112741 x)/840 - (62251 x^2)/480 + (18949 x^3)/288 - (12443 x^4)/640 + (2497 x^5)/720 - (353 x^6)/960 + (43
    // x^7)/2016 - x^8/1920
    // {{1,0},{2,1},{3,1},{4,2},{5,3},{6,5},{7,8},{8,13},{9,21}}
    private final Point[] INPUT_1 =
            new Point[] {p(1, 0), p(2, 1), p(3, 1), p(4, 2), p(5, 3), p(6, 5), p(7, 8), p(8, 13), p(9, 21)};
    // 2 - (25 x)/12 + (16763 x^2)/5040 - (1279 x^3)/720 + (629 x^4)/960 - (5 x^5)/36 + (3 x^6)/160 - x^7/720 +
    // x^8/20160
    // {{1,2},{2,4},{3,8},{4,16},{5,32},{6,64},{7,128},{8,256},{9,512}}
    private final Point[] INPUT_2 =
            new Point[] {p(1, 2), p(2, 4), p(3, 8), p(4, 16), p(5, 32), p(6, 64), p(7, 128), p(8, 256), p(9, 512)};
    // x
    // {{1,1},{4,4},{9,9},{16,16}}
    private final Point[] INPUT_3 = new Point[] {p(1, 1), p(4, 4), p(9, 9), p(16, 16)};

    @Test
    @SuppressWarnings("unchecked")
    void testInvalidInvocationsGroupElementValues() {
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(null, null));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(null, mock(List.class)));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverGroupElement(mock(List.class), null));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverGroupElement(mock(List.class), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverGroupElement(List.of(), mock(List.class)));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverGroupElement(
                        List.of(0), List.of(mock(GroupElement.class), mock(GroupElement.class))));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverGroupElement(List.of(0, 1), List.of(mock(GroupElement.class))));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testInvalidInvocationsFieldElementValues() {
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(null, null));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(null, mock(List.class)));
        assertThrows(NullPointerException.class, () -> Lagrange.recoverFieldElement(mock(List.class), null));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverFieldElement(mock(List.class), List.of()));
        assertThrows(IllegalArgumentException.class, () -> Lagrange.recoverFieldElement(List.of(), mock(List.class)));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverFieldElement(
                        List.of(0), List.of(mock(FieldElement.class), mock(FieldElement.class))));
        assertThrows(
                IllegalArgumentException.class,
                () -> Lagrange.recoverFieldElement(List.of(0, 1), List.of(mock(FieldElement.class))));
    }

    @Test
    void testLagrangeWithKnownFieldElementValues() {
        // Calculated using
        // https://www.wolframalpha.com/input?i=interpolating+polynomial+calculator
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final Field field = curve.field();
        var inputs = inputs(field, INPUT_0);
        assertEquals(field.fromLong(30), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, INPUT_1);
        assertEquals(
                field.fromLong(0).subtract(field.fromLong(54)), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, INPUT_2);
        assertEquals(field.fromLong(2), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
        inputs = inputs(field, INPUT_3);
        assertEquals(field.fromLong(0), Lagrange.recoverFieldElement(inputs.xs(), inputs.ys()));
    }

    @Test
    void testLagrangeWithKnownGroupElementValues() {
        // Calculated using
        // https://www.wolframalpha.com/input?i=interpolating+polynomial+calculator
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final Field field = curve.field();
        var inputs = inputs(field, INPUT_0);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(30)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, INPUT_1);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(0).subtract(field.fromLong(54))),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, INPUT_2);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(2)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
        inputs = inputs(field, INPUT_3);
        assertEquals(
                curve.group1().generator().multiply(field.fromLong(0)),
                Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys())));
    }

    @Test
    void testLargeLagrangeWithKnownGroupElementValues() {
        // Calculated using
        // https://www.wolframalpha.com/input?i=interpolating+polynomial+calculator
        var curve = PairingFriendlyCurves.findInstance(Curve.ALT_BN128);
        final Field field = curve.field();
        var array = IntStream.rangeClosed(1, 2000).boxed().toArray(Integer[]::new);
        var inputs = inputs(field, array);
        var value = Lagrange.recoverGroupElement(inputs.xs(), toPoints(curve.group1(), inputs.ys()));
        System.out.println(value);
    }

    private List<GroupElement> toPoints(final Group group, final List<FieldElement> inputs) {
        return inputs.stream().map(i -> group.generator().multiply(i)).toList();
    }

    private Result inputs(final Field field, final Point... points) {
        var ys = Stream.of(points).map(Point::y).map(field::fromLong).toList();
        var xs = Stream.of(points).map(Point::x).toList();
        return new Result(xs, ys);
    }

    private Result inputs(final Field field, final Integer... integers) {
        var ys = Stream.of(integers).map(field::fromLong).toList();
        var xs = IntStream.rangeClosed(1, ys.size()).boxed().toList();
        return new Result(xs, ys);
    }

    record Point(int x, int y) {
        static Point p(final int x, final int y) {
            return new Point(x, y);
        }
    }

    record Result(List<Integer> xs, List<FieldElement> ys) {}
}
