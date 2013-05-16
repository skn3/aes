Type AESGlue
	Function Lsr:Int( number:Int, shiftBy:Int )
		Return number Shr shiftBy
	End Function
	
	Function Lsl:Int( number:Int, shiftBy:Int )
		Return number Shl shiftBy
	End Function
End Type