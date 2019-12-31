package kr.co.kbiid.license.util;

import java.util.Enumeration;
import java.util.Iterator;

/**
 * HostInfoUtil의 getLocalMacAddresses메서드에서 사용된다.
 *         
 * @author Kim Ki Ju <kbiid@torpedo.co.kr>
 */
class IterableEnumeration<T> implements Iterable<T> {
	private final Enumeration<T> enumeration;

	public IterableEnumeration(Enumeration<T> enumeration) {
		this.enumeration = enumeration;
	}

	// return an adaptor for the Enumeration
	public Iterator<T> iterator() {
		return new Iterator<T>() {
			public boolean hasNext() {
				return enumeration.hasMoreElements();
			}

			public T next() {
				return enumeration.nextElement();
			}

			public void remove() {
				throw new UnsupportedOperationException();
			}
		};
	}

	public static <T> Iterable<T> make(Enumeration<T> en) {
		return new IterableEnumeration<T>(en);
	}

}
