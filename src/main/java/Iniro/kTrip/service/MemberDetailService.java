package Iniro.kTrip.service;


import Iniro.kTrip.domain.Member;
import Iniro.kTrip.dto.MemberDetails;
import Iniro.kTrip.repository.MemberRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class MemberDetailService implements UserDetailsService
{
    private final MemberRepository memberRepository;
    @Autowired
    public MemberDetailService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException
    {
        Member memberData= memberRepository.findById(id);

        if(memberData!=null)
        {
            return new MemberDetails(memberData);
        }
        return null;
    }
}
