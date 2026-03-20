# my_profile.py
import streamlit as st
import pandas as pd
st.title('자기소개')
# 본인 정보 수정하기!
st.write('## 기본 정보')
st.write('**이름**: 김기혁')
st.write('**학과**: 인공지능소프트웨어학과')
st.write('**학년**: 3학년')
st.write('---') # 구분선
st.write('## 이번 학기 시간표')
schedule = pd.DataFrame({
 '요일': ['월', '화', '수', '목', '금'],
 '2교시': ['인공지능라이브러리', '-', '인공지능캡스톤디자인', '-', '빅데이터분석프로젝트'],
 '3교시': ['데이터베이스', '웹프로그래밍', '알고리즘', '웹프로그래밍', '빅데이터분석프로젝트'],
 '4교시': ['-', '웹프로그래밍', '-', '웹프로그래밍', '빅데이터분석프로젝트']
})
st.write(schedule)
st.write('---')
st.write('## 관심 분야')
st.write('- 딥러닝')
st.write('- AI 개발')
st.write('- 게임 개발 ')
st.write('---')
st.write('## 이번 학기 목표')
goals = pd.DataFrame({
 '목표': ['정보처리산업기사', '동아리 프로젝트', '포트폴리오 완성'],
 '달성률': [30, 10, 10]
})
st.write(goals)
st.bar_chart(goals.set_index('목표'))
