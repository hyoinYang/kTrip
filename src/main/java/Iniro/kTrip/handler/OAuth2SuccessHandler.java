package Iniro.kTrip.handler;

import Iniro.kTrip.domain.CustomOAuth2User;
import Iniro.kTrip.domain.Member;
import Iniro.kTrip.jwt.JwtUtil;
import Iniro.kTrip.repository.MemberRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtProvider;
    private final MemberRepository memberRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException{

        String redirectUri = "http://localhost:8080/login/oauth2/code/naver";
        String targetUrl;

        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        String userId = oAuth2User.getName();
        Member member =  memberRepository.findById(userId);
        //MemberDto memberDto = new MemberDto(member.getMember_id(), member.getId(), member.getPassword(), member.getEmail(), member.getNickname(), member.getName());
        String token = jwtProvider.createAccessToken(member, 100000);


        targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .build().toUriString();

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
        //response.sendRedirect("http://localhost:8080/auth/oauth-response/"+token+"/3600");
    }
}
