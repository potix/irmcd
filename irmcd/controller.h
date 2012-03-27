#ifndef CONTROLLER_H
#define CONTROLLER_H

/*
 * iremocon等の外部のコントローラーと通信する部分
 * リクエストをキューに積むと該当するセクションの
 * シナリオファイルを探しそれを実行する
 * キューに詰めた場合はACCEPTを返す
 * そうでない場合はそれ以外を返す
 * キューに積んだ後の成功失敗はログや
 * failScript,successScriptが実行されたかどうか
 * でしかわからない。
 * controllerは別スレッドで動作している
 */

typedef struct controller controller_t;

#define RESULT_ACCEPT		"ACCEPT"
#define RESULT_REJECT		"REJECT"
#define RESULT_BUSY		"BUSY"
#define RESULT_NOT_READY	"NOT_READY"
#define RESULT_INTERNAL_ERROR	"INTERNAL_ERROR"


/* コントローラーを作る */
int controller_create(
    controller_t **controller,
    const char *config_file);

/* コントローラーを削除する */
int controller_destroy(
   controller_t *controller);

/* コントローラーを開始する */
int controller_start(
    controller_t *controller);

/* コントローラーを止める */
int controller_stop(
    controller_t *controller);

/* コントローラーのキューへ積む */
const char *controller_enqueue(
    controller_t *controller,
    char *request);
    
/* コントローラーに必要な設定を読み直す */
int controller_load_config(
    controller_t *controller);

#endif
