package Iniro.kTrip.service;

import Iniro.kTrip.dao.FavoriteRepository;
import Iniro.kTrip.domain.Favorite;
import Iniro.kTrip.domain.Member;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional(readOnly = true)
public class FavoriteService {

    @Autowired
    private FavoriteRepository favoriteRepository;

    public Favorite createFavorite(String cid, String cname, Member member) {
        return Favorite.builder()
                .member(member)
                .cid(cid)
                .cname(cname)
                .build();
    }

    @Transactional
    public void addFavoriteSpot(String cid, String cname, Member member) throws IllegalAccessException {
        if (favoriteRepository.existsByMemberAndCid(member, cid)) {
            throw new IllegalAccessException("이미 즐겨찾기되어있는 여행지입니다.");
        } else {
            favoriteRepository.save(createFavorite(cid, cname,member));
        }
    }

    @Transactional
    public void deleteFavoriteSpot(String cid, Member member) throws IllegalAccessException {
        if (!favoriteRepository.existsByMemberAndCid(member, cid)) {
            throw new IllegalAccessException("즐겨찾기 정보가 없습니다.");
        } else {
            favoriteRepository.deleteFavoriteByMemberAndCid(member, cid);
        }
    }

    @Transactional
    public List<Favorite> favoriteByMid(Member member) {
        return favoriteRepository.findCidByMember(member);
    }
}
