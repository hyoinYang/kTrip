package Iniro.kTrip.openApi;


import lombok.Getter;

@Getter
public enum TripApi {

    //쿼리 파라미터
    END_POINT("http://apis.data.go.kr/B551011/KorService1"),
    TYPE("_type=json"),
    MOBILE_OS("MobileOS=ETC"),
    MOBILE_APP("MobileApp=kTrip"),
    SERVICE_KEY("serviceKey=jJL7RJtEplRWyT4h%252Bo9Cggy%252FZQEb%252FClx%252BSKxloGuo3wy%252FyoauDsMyxqll890ix4J6hKWnwLQP%252BCrn96rmXvXjA%253D%253D"),
    NUM_OF_ROWS("numOfRows=12"),
    PAGE_NO("pageNo=1"),
    LIST_YN("listYN="),
    ARRANGE("arrange="),
    CONTENT_TYPE_ID("contentTypeId="),
    AREA_CODE("areaCode="),
    SIGUNGU_CODE("sigunguCode="),
    CAT1("cat1="),
    CAT2("cat2="),
    CAT3("cat3="),
    MODIFIED_TIME("modifiedtime="),
    //공통정보 조회
    KEYWORD("keyword="),
    DEFAULT_YN("defaultYN="),
    FIRST_IMAGE_YN("firstImageYN="),
    AREA_CODE_YN("areacodeYN="),
    CAT_CODE_YN("catcodeYN="),
    ADDR_INFO_YN("addrinfoYN="),
    MAP_INFO_YN("mapinfoYN="),
    OVERVIEW_YN("overviewYN="),

    CONTENT_ID("contentId="),


    //api목록
    AREA_BASED_LIST1("/areaBasedList1"),
    SEARCH_KEYWORD1("/searchKeyword1"),
    SEARCH_STAY1("/searchStay1"),
    DETAIL_COMMON1("/detailCommon1"),
    DETAIL_INTRO("/detailIntro1"),
    DETAIL_INFO("/detailInfo1"),

    ;

    private final String value;

    TripApi(String value) {
        this.value = value;
    }
}