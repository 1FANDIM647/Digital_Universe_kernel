Program Cals ;
Uses CRT;
Var prog:boolean ;
Var a , b,c,d,e:integer;
Begin
    if  prog = true then  {We are testing program}
    begin
    a:= 0;
    Repeat Until KeyPressed;
    While a = 0  do  
    WriteLn('Calculating system');
    WriteLn('Calculating drivers');
    WriteLn('Checking of programs in your PC');
    GoToXY(60,60);
    end;
   
    if prog = false then 
    begin
      WriteLn('It has mistake ,please fix the problem '); {WE have founded bag}
      GoToXY(60,60);
    end;
end.