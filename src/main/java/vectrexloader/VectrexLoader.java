/* ###
 * IP: GHIDRA
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
package vectrexloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class VectrexLoader extends AbstractLibrarySupportLoader {
	@Override
	public String getName() {
		return "GCE Vectrex";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);
		if (reader.readAsciiString(0, 5).equals("g GCE")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("6809:BE:16:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider,
			LoadSpec loadSpec,
			List<Option> options,
			Program program,
			TaskMonitor monitor,
			MessageLog log) throws CancelledException, IOException {
		InputStream romStream = provider.getInputStream(0);
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		createSegment(fpa, romStream, "ROM_CART",   0x0000L, Math.min(romStream.available(), 0x8000L), true, false, true, false, log);
		createSegment(fpa, null, "NVRAM",           0x8000L, 0x0800L, true, true, false, true, log);
		createSegment(fpa, null, "LED",             0xA000L, 0x0001L, true, true, false, true, log);
		createSegment(fpa, null, "RAM",             0xC800L, 0x0400L, true, true, false, true, log);
		createSegment(fpa, null, "6522_VIA",        0xD000L, 0x0800L, true, true, false, true, log);
		createSegment(fpa, null, "ROM_MINE_STORM",  0xE000L, 0x1000L, true, false, true, true, log);
		createSegment(fpa, null, "ROM_OS",          0xF000L, 0x1000L, true, false, true, true, log);

		MemoryBlock block = fpa.getMemoryBlock(fpa.toAddr(0));
		Address startAddress = block.getStart().getPhysicalAddress();

		Address strAddress = fpa.findBytes(startAddress, "\\x80");
		try {
			fpa.createAsciiString(startAddress, (int) (strAddress.getOffset() - startAddress.getOffset() + 1));
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
		
		Address foundAddress = fpa.findBytes(strAddress.add(1), "\\x80\\x00");
		if (foundAddress == null) {
			throw new RuntimeException("Could not find entry point.");
		}
		fpa.addEntryPoint(foundAddress.add(2));

		fpa.createFunction(fpa.toAddr(0xF000L), "Start");
		fpa.createFunction(fpa.toAddr(0xF06CL), "Warm_Start");
		fpa.createFunction(fpa.toAddr(0xF14CL), "Init_VIA");
		fpa.createFunction(fpa.toAddr(0xF164L), "Init_OS_RAM");
		fpa.createFunction(fpa.toAddr(0xF18BL), "Init_OS");
		fpa.createFunction(fpa.toAddr(0xF192L), "Wait_Recal");
		fpa.createFunction(fpa.toAddr(0xF1A2L), "Set_Refresh");
		fpa.createFunction(fpa.toAddr(0xF1AAL), "DP_to_D0");
		fpa.createFunction(fpa.toAddr(0xF1AFL), "DP_to_C8");
		fpa.createFunction(fpa.toAddr(0xF1B4L), "Read_Btns_Mask");
		fpa.createFunction(fpa.toAddr(0xF1BAL), "Read_Btns");
		fpa.createFunction(fpa.toAddr(0xF1F5L), "Joy_Analog");
		fpa.createFunction(fpa.toAddr(0xF1F8L), "Joy_Digital");
		fpa.createFunction(fpa.toAddr(0xF256L), "Sound_Byte");
		fpa.createFunction(fpa.toAddr(0xF259L), "Sound_Byte_x");
		fpa.createFunction(fpa.toAddr(0xF25BL), "Sound_Byte_raw");
		fpa.createFunction(fpa.toAddr(0xF272L), "Clear_Sound");
		fpa.createFunction(fpa.toAddr(0xF27DL), "Sound_Bytes");
		fpa.createFunction(fpa.toAddr(0xF284L), "Sound_Bytes_x?");
		fpa.createFunction(fpa.toAddr(0xF289L), "Do_Sound");
		fpa.createFunction(fpa.toAddr(0xF28CL), "Do_Sound_x?");
		fpa.createFunction(fpa.toAddr(0xF29DL), "Intensity_1F");
		fpa.createFunction(fpa.toAddr(0xF2A1L), "Intensity_3F");
		fpa.createFunction(fpa.toAddr(0xF2A5L), "Intensity_5F");
		fpa.createFunction(fpa.toAddr(0xF2A9L), "Intensity_7F");
		fpa.createFunction(fpa.toAddr(0xF2ABL), "Intensity_a");
		fpa.createFunction(fpa.toAddr(0xF2BEL), "Dot_ix_b");
		fpa.createFunction(fpa.toAddr(0xF2C1L), "Dot_ix");
		fpa.createFunction(fpa.toAddr(0xF2C3L), "Dot_d");
		fpa.createFunction(fpa.toAddr(0xF2C5L), "Dot_here");
		fpa.createFunction(fpa.toAddr(0xF2D5L), "Dot_List");
		fpa.createFunction(fpa.toAddr(0xF2DEL), "Dot_List_Reset");
		fpa.createFunction(fpa.toAddr(0xF2E6L), "Recalibrate");
		fpa.createFunction(fpa.toAddr(0xF2F2L), "Moveto_x_7F");
		fpa.createFunction(fpa.toAddr(0xF2FCL), "Moveto_d_7F");
		fpa.createFunction(fpa.toAddr(0xF308L), "Moveto_ix_FF");
		fpa.createFunction(fpa.toAddr(0xF30CL), "Moveto_ix_7F");
		fpa.createFunction(fpa.toAddr(0xF30EL), "Moveto_ix_b");
		fpa.createFunction(fpa.toAddr(0xF310L), "Moveto_ix");
		fpa.createFunction(fpa.toAddr(0xF312L), "Moveto_d");
		fpa.createFunction(fpa.toAddr(0xF34AL), "Reset0Ref_D0");
		fpa.createFunction(fpa.toAddr(0xF34FL), "Check0Ref");
		fpa.createFunction(fpa.toAddr(0xF354L), "Reset0Ref");
		fpa.createFunction(fpa.toAddr(0xF35BL), "Reset_Pen");
		fpa.createFunction(fpa.toAddr(0xF36BL), "Reset0Int");
		fpa.createFunction(fpa.toAddr(0xF373L), "Print_Str_hwyx");
		fpa.createFunction(fpa.toAddr(0xF378L), "Print_Str_yx");
		fpa.createFunction(fpa.toAddr(0xF37AL), "Print_Str_d");
		fpa.createFunction(fpa.toAddr(0xF385L), "Print_List_hw");
		fpa.createFunction(fpa.toAddr(0xF38AL), "Print_List");
		fpa.createFunction(fpa.toAddr(0xF38CL), "Print_List_chk");
		fpa.createFunction(fpa.toAddr(0xF391L), "Print_Ships_x");
		fpa.createFunction(fpa.toAddr(0xF393L), "Print_Ships");
		fpa.createFunction(fpa.toAddr(0xF3ADL), "Mov_Draw_VLc_a");
		fpa.createFunction(fpa.toAddr(0xF3B1L), "Mov_Draw_VL_b");
		fpa.createFunction(fpa.toAddr(0xF3B5L), "Mov_Draw_VLcs");
		fpa.createFunction(fpa.toAddr(0xF3B7L), "Mov_Draw_VL_ab");
		fpa.createFunction(fpa.toAddr(0xF3B9L), "Mov_Draw_VL_a");
		fpa.createFunction(fpa.toAddr(0xF3BCL), "Mov_Draw_VL");
		fpa.createFunction(fpa.toAddr(0xF3BEL), "Mov_Draw_VL_d");
		fpa.createFunction(fpa.toAddr(0xF3CEL), "Draw_VLc");
		fpa.createFunction(fpa.toAddr(0xF3D2L), "Draw_VL_b");
		fpa.createFunction(fpa.toAddr(0xF3D6L), "Draw_VLcs");
		fpa.createFunction(fpa.toAddr(0xF3D8L), "Draw_VL_ab");
		fpa.createFunction(fpa.toAddr(0xF3DAL), "Draw_VL_a");
		fpa.createFunction(fpa.toAddr(0xF3DDL), "Draw_VL");
		fpa.createFunction(fpa.toAddr(0xF3DFL), "Draw_Line_d");
		fpa.createFunction(fpa.toAddr(0xF404L), "Draw_VLp_FF");
		fpa.createFunction(fpa.toAddr(0xF408L), "Draw_VLp_7F");
		fpa.createFunction(fpa.toAddr(0xF40CL), "Draw_VLp_scale");
		fpa.createFunction(fpa.toAddr(0xF40EL), "Draw_VLp_b");
		fpa.createFunction(fpa.toAddr(0xF410L), "Draw_VLp");
		fpa.createFunction(fpa.toAddr(0xF434L), "Draw_Pat_VL_a");
		fpa.createFunction(fpa.toAddr(0xF437L), "Draw_Pat_VL");
		fpa.createFunction(fpa.toAddr(0xF439L), "Draw_Pat_VL_d");
		fpa.createFunction(fpa.toAddr(0xF46EL), "Draw_VL_mode");
		fpa.createFunction(fpa.toAddr(0xF495L), "Print_Str");
		fpa.createFunction(fpa.toAddr(0xF511L), "Random_3");
		fpa.createFunction(fpa.toAddr(0xF517L), "Random");
		fpa.createFunction(fpa.toAddr(0xF533L), "Init_Music_Buf");
		fpa.createFunction(fpa.toAddr(0xF53FL), "Clear_x_b");
		fpa.createFunction(fpa.toAddr(0xF542L), "Clear_C8_RAM");
		fpa.createFunction(fpa.toAddr(0xF545L), "Clear_x_256");
		fpa.createFunction(fpa.toAddr(0xF548L), "Clear_x_d");
		fpa.createFunction(fpa.toAddr(0xF550L), "Clear_x_b_80");
		fpa.createFunction(fpa.toAddr(0xF552L), "Clear_x_b_a");
		fpa.createFunction(fpa.toAddr(0xF55AL), "Dec_3_Counters");
		fpa.createFunction(fpa.toAddr(0xF55EL), "Dec_6_Counters");
		fpa.createFunction(fpa.toAddr(0xF563L), "Dec_Counters");
		fpa.createFunction(fpa.toAddr(0xF56DL), "Delay_3");
		fpa.createFunction(fpa.toAddr(0xF571L), "Delay_2");
		fpa.createFunction(fpa.toAddr(0xF575L), "Delay_1");
		fpa.createFunction(fpa.toAddr(0xF579L), "Delay_0");
		fpa.createFunction(fpa.toAddr(0xF57AL), "Delay_b");
		fpa.createFunction(fpa.toAddr(0xF57DL), "Delay_RTS");
		fpa.createFunction(fpa.toAddr(0xF57EL), "Bitmask_a");
		fpa.createFunction(fpa.toAddr(0xF584L), "Abs_a_b");
		fpa.createFunction(fpa.toAddr(0xF58BL), "Abs_b");
		fpa.createFunction(fpa.toAddr(0xF593L), "Rise_Run_Angle");
		fpa.createFunction(fpa.toAddr(0xF5D9L), "Get_Rise_Idx");
		fpa.createFunction(fpa.toAddr(0xF5DBL), "Get_Run_Idx");
		fpa.createFunction(fpa.toAddr(0xF5EFL), "Rise_Run_Idx");
		fpa.createFunction(fpa.toAddr(0xF5FFL), "Rise_Run_X");
		fpa.createFunction(fpa.toAddr(0xF601L), "Rise_Run_Y");
		fpa.createFunction(fpa.toAddr(0xF603L), "Rise_Run_Len");
		fpa.createFunction(fpa.toAddr(0xF610L), "Rot_VL_ab");
		fpa.createFunction(fpa.toAddr(0xF616L), "Rot_VL");
		fpa.createFunction(fpa.toAddr(0xF61FL), "Rot_VL_Mode");
		fpa.createFunction(fpa.toAddr(0xF62BL), "Rot_VL_M_dft");
		fpa.createFunction(fpa.toAddr(0xF65BL), "Xform_Run_a");
		fpa.createFunction(fpa.toAddr(0xF65DL), "Xform_Run");
		fpa.createFunction(fpa.toAddr(0xF661L), "Xform_Rise_a");
		fpa.createFunction(fpa.toAddr(0xF663L), "Xform_Rise");
		fpa.createFunction(fpa.toAddr(0xF67FL), "Move_Mem_a_1");
		fpa.createFunction(fpa.toAddr(0xF683L), "Move_Mem_a");
		fpa.createFunction(fpa.toAddr(0xF687L), "Init_Music_chk");
		fpa.createFunction(fpa.toAddr(0xF68DL), "Init_Music");
		fpa.createFunction(fpa.toAddr(0xF692L), "Init_Music_dft");
		fpa.createFunction(fpa.toAddr(0xF7A9L), "Select_Game");
		fpa.createFunction(fpa.toAddr(0xF835L), "Display_Option");
		fpa.createFunction(fpa.toAddr(0xF84FL), "Clear_Score");
		fpa.createFunction(fpa.toAddr(0xF85EL), "Add_Score_a");
		fpa.createFunction(fpa.toAddr(0xF87CL), "Add_Score_d");
		fpa.createFunction(fpa.toAddr(0xF8B7L), "Strip_Zeros");
		fpa.createFunction(fpa.toAddr(0xF8C7L), "Compare_Score");
		fpa.createFunction(fpa.toAddr(0xF8D8L), "New_High_Score");
		fpa.createFunction(fpa.toAddr(0xF8E5L), "Obj_Will_Hit_u");
		fpa.createFunction(fpa.toAddr(0xF8F3L), "Obj_Will_Hit");
		fpa.createFunction(fpa.toAddr(0xF8FFL), "Obj_Hit");
		fpa.createFunction(fpa.toAddr(0xF92EL), "Explosion_Snd");
		fpa.createFunction(fpa.toAddr(0xFF9FL), "Draw_Grid_VL");

		createNamedData(fpa, program, 0xC800L, "Vec_Snd_Shadow", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC80FL, "Vec_Btn_State", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC810L, "Vec_Prev_Btns", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC811L, "Vec_Buttons", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC812L, "Vec_Button_1_1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC813L, "Vec_Button_1_2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC814L, "Vec_Button_1_3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC815L, "Vec_Button_1_4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC816L, "Vec_Button_2_1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC817L, "Vec_Button_2_2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC818L, "Vec_Button_2_3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC819L, "Vec_Button_2_4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81AL, "Vec_Joy_Resltn", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81BL, "Vec_Joy_1_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81CL, "Vec_Joy_1_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81DL, "Vec_Joy_2_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81EL, "Vec_Joy_2_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC81FL, "Vec_Joy_Mux_1_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC820L, "Vec_Joy_Mux_1_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC821L, "Vec_Joy_Mux_2_X", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC822L, "Vec_Joy_Mux_2_Y", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC823L, "Vec_Misc_Count", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC824L, "Vec_0Ref_Enable", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC825L, "Vec_Loop_Count", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC827L, "Vec_Brightness", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC828L, "Vec_Dot_Dwell", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC829L, "Vec_Pattern", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC82AL, "Vec_Text_Height", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC82BL, "Vec_Text_Width", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC82CL, "Vec_Str_Ptr", Pointer16DataType.dataType, log);
		createNamedData(fpa, program, 0xC82EL, "Vec_Counters", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC82EL, "Vec_Counter_1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC82FL, "Vec_Counter_2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC830L, "Vec_Counter_3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC831L, "Vec_Counter_4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC832L, "Vec_Counter_5", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC833L, "Vec_Counter_6", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC834L, "Vec_RiseRun_Tmp", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC836L, "Vec_Angle", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC837L, "Vec_Run_Index", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC839L, "Vec_Rise_Index", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC83BL, "Vec_RiseRun_Len", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC83CL, "Vec_Tmp", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC83DL, "Vec_Rfrsh_lo", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC83EL, "Vec_Rfrsh_hi", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC83FL, "Vec_Music_Work", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC842L, "Vec_Music_Wk_A", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC843L, "Vec_Wk_9", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC844L, "Vec_Wk_8", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC845L, "Vec_Music_Wk_7", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC846L, "Vec_Music_Wk_6", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC847L, "Vec_Music_Wk_5", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC848L, "Vec_Wk_4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC849L, "Vec_Wk_3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84AL, "Vec_Wk_2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84BL, "Vec_Music_Wk_1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84CL, "Vec_Wk_0", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84DL, "Vec_Freq_Table", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84FL, "Vec_Max_Players", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC850L, "Vec_Max_Games", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC84FL, "Vec_ADSR_Table", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC851L, "Vec_Twang_Table", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC853L, "Vec_Music_Ptr", Pointer16DataType.dataType, log);
		createNamedData(fpa, program, 0xC855L, "Vec_Music_Chan", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC856L, "Vec_Music_Flag", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC857L, "Vec_Duration", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC858L, "Vec_Music_Twang", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC858L, "Vec_Expl_1", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC859L, "Vec_Expl_2", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC85AL, "Vec_Expl_3", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC85BL, "Vec_Expl_4", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC85CL, "Vec_Expl_Chan", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC85DL, "Vec_Expl_ChanB", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC85EL, "Vec_ADSR_Timers", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xC861L, "Vec_Music_Freq", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC867L, "Vec_Expl_Flag", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC877L, "Vec_Expl_Timer", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC879L, "Vec_Num_Players", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC87AL, "Vec_Num_Game", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xC87BL, "Vec_Seed_Ptr", Pointer16DataType.dataType, log);
		createNamedData(fpa, program, 0xC87DL, "Vec_Random_Seed", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xCBEAL, "Vec_Default_Stk", ByteDataType.dataType, log);
		createNamedData(fpa, program, 0xCBEBL, "Vec_High_Score", UnsignedInteger7DataType.dataType, log);
		createNamedData(fpa, program, 0xCBF2L, "Vec_SWI2_Vector", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xCBF5L, "Vec_FIRQ_Vector", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xCBF8L, "Vec_IRQ_Vector", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xCBFBL, "Vec_SWI_Vector", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xCBFBL, "Vec_NMI_Vector", UnsignedInteger3DataType.dataType, log);
		createNamedData(fpa, program, 0xCBFEL, "Vec_Cold_Flag", ByteDataType.dataType, log);

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegment(FlatProgramAPI fpa,
			InputStream stream,
			String name,
			long address,
			long size,
			boolean read,
			boolean write,
			boolean execute,
			boolean volatil,
			MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa,
			Program program,
			long address,
			String name,
			DataType type,
			MessageLog log) {
		try {
			if (type.equals(ByteDataType.dataType)) {
				fpa.createByte(fpa.toAddr(address));
			} else if (type.equals(WordDataType.dataType)) {
				fpa.createWord(fpa.toAddr(address));
			} else if (type.equals(DWordDataType.dataType)) {
				fpa.createDWord(fpa.toAddr(address));
			}
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (Exception e) {
			log.appendException(e);
		}
	}
}
