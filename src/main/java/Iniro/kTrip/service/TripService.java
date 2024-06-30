package Iniro.kTrip.service;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.parser.JSONParser;
import org.apache.tomcat.util.http.fileupload.IOUtils;
import org.json.JSONArray;
import org.json.simple.JSONObject;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static Iniro.kTrip.openApi.TripApi.*;
import static Iniro.kTrip.openApi.TripApi.TripEndpoint.*;
import static Iniro.kTrip.openApi.TripApi.TripQueryParam.*;
import static Iniro.kTrip.util.URLBuilder.fetch;

@Service
@Slf4j
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class TripService {

    public static List<?> recommendTrip(String areaCode, String sigunguCode, String contenttypeid, String pageNo, String cat1) throws URISyntaxException {
        String area_code = areaCode != null ? areaCode : "";
        String sigungu_code = sigunguCode != null ? sigunguCode : "";
        String content_type_id = contenttypeid != null ? contenttypeid : "";
        String page_no = pageNo != null ? pageNo : "1";
        String category1 = cat1 != null ? cat1 : "";
        String reqUrl = AREA_BASED_LIST1.getEndPoint() + "?" +
                AREA_CODE.getParam() + area_code + "&" +
                SIGUNGU_CODE.getParam() + sigungu_code + "&" +
                CONTENT_TYPE_ID.getParam() + content_type_id + "&" +
                PAGE_NO.getParam() + page_no + "&" +
                CAT1.getParam() + category1;

        return fetch(reqUrl);
    }


    public static Object getDetailIntro(String contentId, String contentTypeId) throws URISyntaxException {
        String reqUrl = null;
        String content_type_id = contentTypeId != null ? contentTypeId : "";
        String content_id = contentTypeId != null ? contentId : "";
        try {
            reqUrl = DETAIL_INTRO1.getEndPoint() +
                    "?" + CONTENT_TYPE_ID.getParam() + content_type_id +
                    "&" + CONTENT_ID.getParam() + content_id;

        } catch (Exception e) {
            log.error("{}", e);
        }
        return fetch(reqUrl);
    }
    public static Object getDetailInfo(String contentId, String contentTypeId) throws URISyntaxException {
        String reqUrl = null;
        String content_type_id = contentTypeId != null ? contentTypeId : "";
        String content_id = contentTypeId != null ? contentId : "";
        try {
            reqUrl = DETAIL_INFO1.getEndPoint() +
                    "?" + CONTENT_TYPE_ID.getParam() + content_type_id +
                    "&" + CONTENT_ID.getParam() + content_id;

        } catch (Exception e) {
            log.error("{}", e);
        }
        return fetch(reqUrl);
    }
    public static Object getDetailCommon(String contentId, String contentTypeId) throws URISyntaxException {
        String reqUrl = null;
        String content_type_id = contentTypeId != null ? contentTypeId : "";
        String content_id = contentTypeId != null ? contentId : "";
        String page_no =  "1";
        try {
            reqUrl = DETAIL_COMMON1.getEndPoint() +
                    "?" + CONTENT_TYPE_ID.getParam() + content_type_id +
                    "&" + CONTENT_ID.getParam() + content_id +
                    "&" + PAGE_NO.getParam() + page_no +
                    "&" + DEFAULT_YN.getParam() +
                    "&" + FIRST_IMAGE_YN.getParam() +
                    "&" + AREA_CODE_YN.getParam() +
                    "&" + CAT_CODE_YN.getParam() +
                    "&" + ADDR_INFO_YN.getParam() +
                    "&" + MAP_INFO_YN.getParam() +
                    "&" + OVERVIEW_YN.getParam();
        } catch (Exception e) {
            log.error("{}", e);
        }
        return fetch(reqUrl);
    }
    public Object getTripByKeyword(String keyword, String pageNo) throws URISyntaxException {
        String reqUrl = null;
        String keyWord = keyword != null ? keyword : "";
        String page_no = pageNo != null ? pageNo : "1";
        try {
            reqUrl = SEARCH_KEYWORD1.getEndPoint() +
                    "?" + KEYWORD.getParam() + keyWord +
                    "&" + PAGE_NO.getParam() + page_no;
        } catch (Exception e) {
            log.error("{}", e);
        }
        return fetch(reqUrl);
    }

    public Object recommendByLocation(String mapX, String mapY, String radius, String pageNo) {
        //radius null이면 기본으로 max값 적용(2000)
        try{
            if (radius == null) {
                radius = "2000";
            }
            String page_no = pageNo != null ? pageNo : "1";
            String reqUrl = LOCATION_BASED_LIST1.getEndPoint()
                    + "?" + MAP_X.getParam() + mapX
                    + "&" + MAP_Y.getParam() + mapY
                    + "&" + RADIUS.getParam() + radius
                    + "&" + PAGE_NO.getParam() + page_no
                    ;
            return fetch(reqUrl);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

    public List<?> getStay(String areaCode, String sigunguCode) {
        try{
            String area_code = areaCode != null ? areaCode : "";
            String sigugn_code = sigunguCode != null ? sigunguCode : "";

            String reqUrl = SEARCH_STAY1.getEndPoint() +
                    "?" + AREA_CODE.getParam() + area_code +
                    "&" + SIGUNGU_CODE.getParam() + sigugn_code;
            return fetch(reqUrl);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }

    }

    public Object getTripInfo(String contentId) {
        String reqUrl = null;
        try {
            reqUrl = DETAIL_COMMON1.getEndPoint() +
                    "?" + CONTENT_ID.getParam() + contentId +
                    "&" + DEFAULT_YN.getParam() + "Y" +
                    "&" + FIRST_IMAGE_YN.getParam() + "Y" +
                    "&" + AREA_CODE_YN.getParam() + "Y" +
                    "&" + CAT_CODE_YN.getParam() + "Y" +
                    "&" + ADDR_INFO_YN.getParam() + " Y" +
                    "&" + MAP_INFO_YN.getParam() + "Y" +
                    "&" + OVERVIEW_YN.getParam() + "Y";

        } catch (Exception e) {
            log.error("{}", e);

        }
        return fetchJson(reqUrl);

    }

    public Object fetchJson(String url) { //dto로 변환 필요
        return reqOpenApi(url);

    }

    public JSONArray reqOpenApi(String url) {
        JSONObject jsonObject = null;

        try {
            RestTemplate restTemplate = new RestTemplate();
//            String jsonString = restTemplate.getForObject(makeUrl(url), String.class);
//            log.info("{}", jsonString);
            URL url1 = new URL(makeUrl(url));
            InputStream in = url1.openStream();

            ByteArrayOutputStream bos1 = new ByteArrayOutputStream();
            IOUtils.copy(in, bos1);
            in.close();
            bos1.close();

            String mobs = bos1.toString("UTF-8");

            byte[] b = mobs.getBytes("UTF-8");
            String s = new String(b, "UTF-8");



            JSONParser jsonParser = new JSONParser();

            jsonObject = (JSONObject) jsonParser.parse(s);
            log.info("{}", jsonObject);
        } catch (Exception e) {
            log.error("{}", e);
            throw new RuntimeException(e);
        }
        // 가장 큰 JSON 객체 response 가져오기
        JSONObject jsonResponse = (JSONObject) jsonObject.get("response");

        // 그 다음 body 부분 파싱
        JSONObject jsonBody = (JSONObject) jsonResponse.get("body");

        // 그 다음 위치 정보를 배열로 담은 items 파싱
        JSONObject jsonItems = (JSONObject) jsonBody.get("items");

        // items는 JSON ->  그걸 또 배열로 가져온다
        JSONArray jsonItemList = (JSONArray) jsonItems.get("item");

        return jsonItemList;
    }

    public Object getTripIntro(String contentId, String contentTypeId) {
        String reqUrl = null;
        try {
            reqUrl = DETAIL_INTRO.getEndPoint() +
                    "?" + CONTENT_TYPE_ID.getParam() + contentTypeId +
                    "&" + CONTENT_ID.getParam() + contentId;

        } catch (Exception e) {
            log.error("{}", e);
        }
        return fetchJson(reqUrl);
    }

    private String makeUrl(String url) {
        StringBuffer sbf = new StringBuffer();
        sbf.append(END_POINT.getParam());
        sbf.append(url);
        sbf.append("&");
        sbf.append(MOBILE_APP.getParam());
        sbf.append("&");
        sbf.append(MOBILE_OS.getParam());
        sbf.append("&");
        sbf.append(SERVICE_KEY.getParam());
        sbf.append("&");
        sbf.append(TYPE.getParam());
        System.out.println(sbf.toString());
        return sbf.toString();
    }

    public Object getStayInfo(String contentId, String contentTypeId) {
        String reqUrl = null;
        try {
            reqUrl = DETAIL_INFO.getEndPoint() +
                    "?" + CONTENT_TYPE_ID.getParam() + contentTypeId +
                    "&" + CONTENT_ID.getParam() + contentId;
        } catch (Exception e) {
            log.error("{}", e);
        }

        return fetchJson(reqUrl);

    }


    public Object recommendX(String areaCode, String sigunguCode, String cat1, String cat2, String cat3) throws URISyntaxException {
        cat3 = cat3 != null ? cat3 : "";
        String reqUrl = AREA_BASED_LIST1.getEndPoint()
                + "?" + CAT1.getParam() + cat1
                + "&" + CAT2.getParam() + cat2
                + "&" + CAT3.getParam() + cat3;

        if (areaCode == null) {
            //모든 음식점 조회
            return fetch(reqUrl)
                    ;

        } else {
            reqUrl += "&" + AREA_CODE.getParam() + areaCode;
            if (sigunguCode == null) {
                return fetch(reqUrl);
            } else {
                reqUrl += "&" + SIGUNGU_CODE.getParam() + sigunguCode;
                return fetch(reqUrl);
            }

        }
    }

    public Object recommendFood(String areaCode, String sigunguCode, String cat3) throws URISyntaxException {
        String area_code = areaCode != null ? areaCode : "";
        String sigungu_code = sigunguCode != null ? sigunguCode : "";
        return recommendX(area_code, sigungu_code, "A05", "A0502", cat3);
    }

    public Object recommendShopping(String areaCode, String sigunguCode, String cat3) throws URISyntaxException {
        String area_code = areaCode != null ? areaCode : "";
        String sigungu_code = sigunguCode != null ? sigunguCode : "";
        return recommendX(area_code, sigungu_code, "A04", "A0401", cat3);
    }
}