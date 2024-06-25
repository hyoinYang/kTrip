package Iniro.kTrip.service;

import Iniro.kTrip.domain.CustomOAuth2User;
import Iniro.kTrip.domain.Member;
import Iniro.kTrip.repository.MemberRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class OAuth2UserServiceImplement extends DefaultOAuth2UserService {

    private final MemberRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException{
        OAuth2User oAuth2User = super.loadUser(request);
        String oauthClientName = request.getClientRegistration().getClientName();

        try{
            System.out.println(new ObjectMapper().writeValueAsString(oAuth2User.getAttributes()));
        }catch (Exception e){
            e.printStackTrace();
        }
        Member member = null;
        String userId = null;
        String email = "email";
        String name = null;


        if (oauthClientName.equals("Naver")){
            Map<String, String> responseMap = (Map<String, String>) oAuth2User.getAttributes().get("response");
            userId = "naver_" + responseMap.get("id").substring(0, 14);
            email = responseMap.get("email");
            name = responseMap.get("name");
            member = new Iniro.kTrip.domain.Member(userId, "nickname", email, "naver");
        }


        if (Objects.isNull(member)){
            System.out.println("ERROR: oauth2 로그인 도중 member이 null");
        }
        else{
            if (!userRepository.existsById(member.getId())){
                userRepository.save(member);
            }
        }

        return new CustomOAuth2User(userId);
    }
}