class AESGlue {
	public static int Lsr( int number, int shiftBy ) {
		return (int)((uint)number >> shiftBy);
	}
	public static int Lsl( int number, int shiftBy ) {
		return (int)((uint)number << shiftBy);
	}
}