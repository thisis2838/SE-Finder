# SE-Finder
 
SE-Finder is a command line utility that automatically searches for various functions and variables in the Source Engine useful for speedrun-related game hacking projects like Source Pause Tool.

## How it works
The goal of SE-Finder is to rely as little as possible on Signatures to directly find functions and variables, and instead do light reverse engineering based on specific Engine quirks.

Methods for finding functions include:
* References to identifiable data such as Strings, Floats, etc..
* VFTable jumping
* Cross-referencing function calls

## Support range
SE-Finder was created to support as many engine versions as possible; however, some functions and variables will not be fully supported due to version-specific problems.

This table will list all functions and variables that the tool will seek out for, and the general support range of the tool. (WORK IN PROGRESS)

<table style="undefined;table-layout: fixed; width: 1082px">
<colgroup>
<col style="width: 173px">
<col style="width: 215px">
<col style="width: 99px">
<col style="width: 105px">
<col style="width: 98px">
<col style="width: 98px">
<col style="width: 98px">
<col style="width: 98px">
<col style="width: 98px">
</colgroup>
<thead>
  <tr>
    <th rowspan="2">Module / DLL</th>
    <th rowspan="2">Supported Functions<br>and Variables</th>
    <th colspan="7">Support range</th>
  </tr>
  <tr>
    <td>SE2003</td>
    <td>SE2004</td>
    <td>SE2006</td>
    <td>SE2007</td>
    <td>SE2009</td>
    <td>SE2013</td>
    <td>SE2011</td>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="2">VGUIMatSurface</td>
    <td>StartDrawing()</td>
    <td>❌</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>FinishDrawing()</td>
    <td>❌</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td rowspan="8">Engine</td>
    <td>SpawnPlayer()</td>
    <td></td>
    <td>❌</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>FinishRestore()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>SetPaused()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>Record()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>SV_ActivateServer()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>Host_Runframe()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>Host_AccumulateTime()</td>
    <td></td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
  </tr>
  <tr>
    <td>SV_Frame()</td>
    <td></td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>✔️</td>
    <td>❌</td>
  </tr>
  <tr>
    <td rowspan="7">Client</td>
    <td>DoImageSpaceMotionBlur()</td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>HudUpdate()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>GetButtonBits()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>Shake()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>Fade()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>AdjustAngles()</td>
    <td></td>
    <td>➖</td>
    <td>➖</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>CreateMove()</td>
    <td></td>
    <td>✔️</td>
    <td>✔️</td>
    <td></td>
    <td>✔️</td>
    <td></td>
    <td></td>
  </tr>
</tbody>
</table>
