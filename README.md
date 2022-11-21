# RuRFID_C-version

Реализация протокола RFID на языке *Си*.

Содержит 7 файлов (3 из них - заголовочные):

"**rfid.c**" содержит основной алгоритм взаимодействия метки (*Tag*) и устройства (*Interrogator*).

"**interacting.c**" содержит реализацию основных действий, выполняемых меткой и устройством в рамках протокола, а также некоторые вспомогательные функции, описание которых не приведено в тексте протокола и которые нужны лишь для задания конкретных числовых значений.

"**magma.c**" и "**Kuznyechik.c**" реализуют шифры "Магма" и "Кузнечик" соответственно со всеми необходимыми режимами работы.


Перед запуском необходимо в файле "**interacting.h**" выбрать алгоритм шифрования (параметр "*CIPHER*" - шифр "Магма" или "Кузнечик") и задать значения параметров "*AUTHMETHOD*" и "*PROTMODE*".

Во время работы создаёт/переписывает файл "**log.txt**", в котором отражается весь "диалог" между меткой и устройством.


В папке **LOG** содержится список конкретных параметров для всех режимов и обоих алгоритмов шифрования, а также результаты работы программы на этих параметрах.
