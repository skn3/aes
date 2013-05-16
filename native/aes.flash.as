class AESGlue  {
	public static function Lsr( number:Number, shiftBy:Number ):Number {
		return number >>> shiftBy;
	}
	public static function Lsl function( number:Number, shiftBy:Number ):Number {
		return number << shiftBy;
	}
}